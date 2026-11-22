"""Bounded, credential-checked local observation channel; no PF acknowledgement.

FreeBSD LOCAL_CREDS_PERSISTENT supplies SCM_CREDS2 for every datagram. A message
is accepted only from the configured resolver PID and real/effective UID.
Authentication identifies the producer, not the correctness of its DNS data;
TTL/profile validation is a separate required step.
"""
import array
import base64
import hashlib
import errno
from dataclasses import dataclass
import json
import math
import os
import re
import socket
import struct
import sys
import time
import types
import zlib

MAX_MESSAGE=60000
SENDER_BUFFER_BYTES=65536
CHUNK_BYTES=4096
MAX_DATAGRAM=6000
MAX_GROUPS=128
HEADER=struct.Struct('=iiIIIIi')
RR_FORMAT='dnsalias-rrsets-1'
RR_FIELDS=frozenset(('name','type','class','rrset_flags','rrset_id','rrset_ttl','rdata_hex','raw_ttl'))
RR_MAX_GROUPS=64
RR_MAX_RECORDS=256
ACK_MAGIC=b'DAAK\x01\0\0\0'
ACK_STATUSES=('applied','ignored','helper_error')
ACK_TOKEN=re.compile('[a-f0-9]{32}').fullmatch
NATIVE_MAGIC=b'DARW\x01\0\0\0'
_NATIVE_WIRE=None


class RejectedMessage(ValueError): pass
class IncompleteMessage(BlockingIOError): pass
class RetiredMessage(BlockingIOError): pass


def configure_native_wire(module):
    """Startup-only opt-in after independently pinned native loading."""
    global _NATIVE_WIRE
    if module is not None:
        if (type(module) is not types.ModuleType or module.__name__!='_dnsalias_replywire'
            or getattr(module,'WIRE_ABI',None)!='cpython-311-freebsd-amd64'
            or type(getattr(module,'WIRE_PROTOCOL',None)) is not int or module.WIRE_PROTOCOL!=1
            or any(type(getattr(module,name,None)) is not types.BuiltinFunctionType
                   for name in ('pack','unpack','pack_ack','unpack_ack'))):
            raise ValueError('qualified native codec module required')
    _NATIVE_WIRE=module


@dataclass(frozen=True)
class Credentials:
    pid: int
    uid: int
    euid: int
    gid: int
    egid: int


def parse_sockcred2(raw, *, expected_uid, expected_pid,retired_pid=None):
    if type(expected_uid) is not int or not 0<=expected_uid<2**32 or type(expected_pid) is not int or expected_pid<=0:
        raise ValueError('explicit trusted process identity required')
    if retired_pid is not None and (type(retired_pid) is not int or not 0<retired_pid<2**31 or retired_pid==expected_pid):
        raise ValueError('one distinct explicitly retired native PID required')
    if len(raw)<HEADER.size: raise RejectedMessage('short kernel credentials')
    version,pid,uid,euid,gid,egid,groups=HEADER.unpack_from(raw)
    if version!=0 or not 0<=groups<=MAX_GROUPS or len(raw)!=HEADER.size+groups*4:
        raise RejectedMessage('unsupported kernel credential layout')
    if pid not in (expected_pid,retired_pid) or uid!=expected_uid or euid!=expected_uid:
        raise RejectedMessage('untrusted sender process')
    return Credentials(pid,uid,euid,gid,egid)


def credentials_from_ancillary(items, flags, *, expected_uid, expected_pid,retired_pid=None):
    credentials=[]; unexpected=False
    # recvmsg installs SCM_RIGHTS descriptors even if the payload is rejected.
    # Close all delivered descriptors before any early return or exception.
    for level,kind,raw in items:
        if level==socket.SOL_SOCKET and kind==getattr(socket,'SCM_RIGHTS',1):
            fds=array.array('i');fds.frombytes(raw[:len(raw)-(len(raw)%fds.itemsize)])
            for fd in fds:
                try: os.close(fd)
                except OSError: pass
            unexpected=True
        elif level==socket.SOL_SOCKET and kind==getattr(socket,'SCM_CREDS2',8):
            credentials.append(raw)
        else: unexpected=True
    if flags & (getattr(socket,'MSG_TRUNC',16)|getattr(socket,'MSG_CTRUNC',32)):
        raise RejectedMessage('truncated message or credentials')
    if unexpected or len(credentials)!=1:
        raise RejectedMessage('missing, duplicate or unexpected control data')
    return parse_sockcred2(credentials[0],expected_uid=expected_uid,expected_pid=expected_pid,retired_pid=retired_pid)


def strict_pairs(items):
    result={}
    for key,value in items:
        if key in result: raise RejectedMessage('duplicate JSON key')
        result[key]=value
    return result


def invalid_number(value): raise RejectedMessage('non-finite JSON value')


def finite_float(value):
    parsed=float(value)
    if not math.isfinite(parsed): raise RejectedMessage('non-finite JSON value')
    return parsed


def _rr_metadata(name,kind,klass,flags,identity,ttl):
    return (type(name) is str and 1<=len(name)<=254
        and type(kind) is str and kind in ('A','AAAA','CNAME')
        and type(klass) is str and klass=='IN'
        and type(flags) is int and 0<=flags<2**32
        and type(identity) is int and 0<=identity<2**64
        and type(ttl) is int and 0<=ttl<2**63)


def _rr_datum(encoded,ttl):
    return (type(encoded) is str and len(encoded)<=510
        and type(ttl) is int and 0<=ttl<2**63)


def _rr_repeated_bound(name,kind,klass,flags,identity,ttl):
    # Measure escaped metadata once per group. Another 96 bytes cover all
    # record keys/punctuation, even after removing the compact row brackets.
    # RDATA/TTL bytes and the full header already occur in the encoded input.
    # Do not multiply every ASCII character by the Unicode worst case: that
    # would make large ordinary replies needlessly fall back to fragmentation.
    return len(json.dumps((name,kind,klass,flags,identity,ttl),separators=(',',':')).encode())+96


def _rr_envelope(reply):
    """Group repeated metadata only; retain each RDATA/TTL pair and its order.

    Small replies and unsupported schemas use the original envelope. This
    standalone function is also embedded in the resolver's sender source.
    """
    if type(reply) is not dict:return None
    records=reply.get('records')
    if type(records) is not list or not 8<=len(records)<=RR_MAX_RECORDS:return None
    groups=[];previous=None;extra=512
    for row in records:
        if type(row) is not dict or row.keys()!=RR_FIELDS:return None
        name,kind,klass,flags=row['name'],row['type'],row['class'],row['rrset_flags']
        identity,rrttl=row['rrset_id'],row['rrset_ttl']
        encoded,ttl=row['rdata_hex'],row['raw_ttl']
        if not _rr_metadata(name,kind,klass,flags,identity,rrttl) or not _rr_datum(encoded,ttl):return None
        key=(name,kind,klass,flags,identity,rrttl)
        if key!=previous:
            if len(groups)==RR_MAX_GROUPS:return None
            groups.append([name,kind,klass,flags,identity,rrttl,[]]);previous=key
            cost=_rr_repeated_bound(name,kind,klass,flags,identity,rrttl)
        groups[-1][6].append([encoded,ttl]);extra+=cost
    header=dict(reply);del header['records']
    return {'format':RR_FORMAT,'reply':header,'rrsets':groups},extra


def _rr_unpack(frame,encoded_size):
    """Bound expansion before allocating records; grant no trust or TTL authority."""
    if (type(frame) is not dict or set(frame)!={'format','reply','rrsets'}
        or frame['format']!=RR_FORMAT or type(frame['reply']) is not dict
        or 'records' in frame['reply']):raise RejectedMessage('invalid grouped reply envelope')
    if type(encoded_size) is not int or not 1<=encoded_size<=MAX_MESSAGE:
        raise RejectedMessage('invalid grouped reply size')
    groups=frame['rrsets']
    if type(groups) is not list or not 1<=len(groups)<=RR_MAX_GROUPS:
        raise RejectedMessage('invalid grouped reply count')
    count=0;extra=512
    for group in groups:
        if type(group) is not list or len(group)!=7:raise RejectedMessage('invalid record group shape')
        name,kind,klass,flags,identity,ttl,rows=group
        if not _rr_metadata(name,kind,klass,flags,identity,ttl) or type(rows) is not list or not rows:
            raise RejectedMessage('invalid record group metadata')
        count+=len(rows);extra+=len(rows)*_rr_repeated_bound(name,kind,klass,flags,identity,ttl)
        if count>RR_MAX_RECORDS or encoded_size+extra>MAX_MESSAGE:
            raise RejectedMessage('expanded reply size limit')
        for row in rows:
            if type(row) is not list or len(row)!=2 or not _rr_datum(*row):
                raise RejectedMessage('invalid grouped record value')
    records=[]
    for name,kind,klass,flags,identity,rrttl,rows in groups:
        records.extend({'name':name,'type':kind,'class':klass,'rrset_flags':flags,
            'rrset_id':identity,'rrset_ttl':rrttl,'rdata_hex':encoded,'raw_ttl':ttl} for encoded,ttl in rows)
    return frame['reply']|{'records':records}


def _reply_envelope(item):
    """Validate an envelope already decoded by the strict JSON reader."""
    if not isinstance(item,dict) or set(item)!={'format','reply'} or item['format']!='dnsalias-reply-1' or not isinstance(item['reply'],dict):
        raise RejectedMessage('unsupported reply envelope')
    return item['reply']


def _decoded_reply(item, size):
    if isinstance(item, dict) and item.get('format') == RR_FORMAT:
        return _rr_unpack(item, size)
    return _reply_envelope(item)


def _encode_ack(reply):
    """A fixed 25-byte envelope; it confers no authority or new status.

    Exact shapes only. Unknown fields or types keep the original JSON path,
    so this optimization never hides data from the ordinary ACK validator.
    """
    if type(reply) is not dict or reply.keys()!={'request_id','status'}:
        return None
    token,status=reply['request_id'],reply['status']
    if (any(type(key) is not str for key in reply) or type(token) is not str
        or not ACK_TOKEN(token) or type(status) is not str or status not in ACK_STATUSES):
        return None
    return ACK_MAGIC+bytes.fromhex(token)+bytes((ACK_STATUSES.index(status)+1,))


def _decode_ack(payload):
    if _NATIVE_WIRE is not None:
        try:return _NATIVE_WIRE.unpack_ack(payload)
        except (ValueError,UnicodeError) as exc:raise RejectedMessage('invalid native acknowledgment') from exc
    if len(payload)!=25 or payload[:8]!=ACK_MAGIC or not 1<=payload[24]<=len(ACK_STATUSES):
        raise RejectedMessage('invalid compact acknowledgment')
    return {'request_id':payload[8:24].hex(),'status':ACK_STATUSES[payload[24]-1]}


def decode_payload(payload):
    if not 1<=len(payload)<=MAX_MESSAGE: raise RejectedMessage('message size limit')
    if payload[:8]==ACK_MAGIC:return _decode_ack(payload)
    try:
        item=json.loads(payload.decode('utf-8'),object_pairs_hook=strict_pairs,parse_constant=invalid_number,parse_float=finite_float)
    except (UnicodeError,ValueError,RecursionError) as exc:
        raise RejectedMessage('invalid message encoding') from exc
    return _decoded_reply(item, len(payload))


def _compressed_reply(frame):
    """Decode one bounded transport frame, then apply the ordinary strict reader.

    Compression never changes the permitted expanded size or DNS validation.
    Nested streams, trailing data and a false advertised length are rejected.
    """
    if set(frame)!={'format','size','data'} or type(frame['size']) is not int or not CHUNK_BYTES<frame['size']<=MAX_MESSAGE:
        raise RejectedMessage('invalid compressed message geometry')
    if type(frame['data']) is not str or not 1<=len(frame['data'])<=5464:
        raise RejectedMessage('invalid compressed message data')
    try:
        compressed=base64.b64decode(frame['data'],validate=True)
        decoder=zlib.decompressobj()
        payload=decoder.decompress(compressed,frame['size']+1)
    except (ValueError,UnicodeError,zlib.error) as exc:
        raise RejectedMessage('invalid compressed message') from exc
    if len(payload)!=frame['size'] or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise RejectedMessage('compressed message length or stream mismatch')
    return decode_payload(payload)


def configure_sender(sock):
    """Bounded per-socket capacity; never change a kernel/global socket limit."""
    if sock.family!=socket.AF_UNIX or sock.type!=socket.SOCK_DGRAM:
        raise ValueError('local datagram socket required')
    sock.setblocking(False)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF,SENDER_BUFFER_BYTES)
    if sock.getsockopt(socket.SOL_SOCKET,socket.SO_SNDBUF)<SENDER_BUFFER_BYTES:
        raise RuntimeError('socket send capacity is below the bounded queue requirement')


def configure_receiver(sock):
    if not sys.platform.startswith('freebsd') or not hasattr(socket,'LOCAL_CREDS_PERSISTENT') or not hasattr(socket,'SCM_CREDS2'):
        raise RuntimeError('qualified FreeBSD credential support required')
    if sock.family!=socket.AF_UNIX or sock.type!=socket.SOCK_DGRAM:
        raise ValueError('local datagram socket required')
    # SOL_LOCAL is 0 in FreeBSD sys/un.h; Python 3.11 does not expose its name.
    sock.setsockopt(0,socket.LOCAL_CREDS_PERSISTENT,1)
    sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
    sock.setblocking(False)


class MessageAssembler:
    """Fixed deadlines and aggregate caps; only authenticated fragments may enter.

    Receivers must treat discarded messages as a coverage gap. Partial messages
    are never delivered to mapping or PF code. No wall-clock lease is extended.
    """
    def __init__(self):
        self.pending={};self.bytes=0;self.discarded=0;self.last_clock=None

    def _discard(self,key):
        entry=self.pending.pop(key,None)
        if entry: self.bytes-=sum(map(len,entry['parts'].values()));self.discarded+=1

    def advance(self,now):
        """Expire incomplete messages even when no further datagrams arrive."""
        if type(now) not in (int,float) or not math.isfinite(now) or now<0: raise RejectedMessage('invalid assembly clock')
        if self.last_clock is not None and now<self.last_clock:
            for key in list(self.pending): self._discard(key)
            raise RejectedMessage('assembly clock moved backwards')
        self.last_clock=now
        for key,entry in list(self.pending.items()):
            if now>=entry['expires']: self._discard(key)

    def accept(self,payload,credential,now):
        if not isinstance(credential,Credentials): raise RejectedMessage('authenticated credentials required')
        self.advance(now)
        if not 1<=len(payload)<=MAX_DATAGRAM: raise RejectedMessage('datagram size limit')
        if payload[:8]==NATIVE_MAGIC:
            if _NATIVE_WIRE is None:raise RejectedMessage('native observation codec is not enabled')
            try:return _NATIVE_WIRE.unpack(payload)
            except (ValueError,UnicodeError) as exc:raise RejectedMessage('invalid native observation') from exc
        try:
            frame=json.loads(payload.decode('utf-8'),object_pairs_hook=strict_pairs,parse_constant=invalid_number,parse_float=finite_float)
        except (UnicodeError,ValueError,RecursionError) as exc: raise RejectedMessage('invalid datagram') from exc
        if isinstance(frame,dict) and frame.get('format') in ('dnsalias-reply-1','dnsalias-rrsets-1'): return _decoded_reply(frame,len(payload))
        if isinstance(frame,dict) and frame.get('format')=='dnsalias-zlib-1': return _compressed_reply(frame)
        fields={'format','id','index','count','size','digest','data'}
        if not isinstance(frame,dict) or set(frame)!=fields or frame['format']!='dnsalias-fragment-1': raise RejectedMessage('unsupported fragment')
        def hexvalue(value,size): return type(value) is str and len(value)==size and all(c in '0123456789abcdef' for c in value)
        if not hexvalue(frame['id'],32) or not hexvalue(frame['digest'],64): raise RejectedMessage('invalid fragment identity')
        size,count,index=frame['size'],frame['count'],frame['index']
        if any(type(n) is not int for n in (size,count,index)) or not CHUNK_BYTES<size<=MAX_MESSAGE or count!=(size+CHUNK_BYTES-1)//CHUNK_BYTES or not 0<=index<count:
            raise RejectedMessage('invalid fragment geometry')
        if type(frame['data']) is not str or len(frame['data'])>5464: raise RejectedMessage('invalid fragment data')
        try: chunk=base64.b64decode(frame['data'],validate=True)
        except (ValueError,UnicodeError) as exc: raise RejectedMessage('invalid base64') from exc
        if len(chunk)!=min(CHUNK_BYTES,size-index*CHUNK_BYTES): raise RejectedMessage('fragment length mismatch')
        key=(credential,frame['id']);metadata=(size,count,frame['digest'])
        entry=self.pending.get(key)
        if entry and entry['metadata']!=metadata:
            self._discard(key);raise RejectedMessage('conflicting fragment metadata')
        if entry and index in entry['parts']:
            if entry['parts'][index]!=chunk: self._discard(key);raise RejectedMessage('conflicting fragment content')
            return None
        if (entry is None and len(self.pending)>=32) or self.bytes+len(chunk)>256*1024:
            self._discard(key);self.discarded+=1;raise RejectedMessage('assembly capacity limit')
        if entry is None:
            entry={'metadata':metadata,'expires':now+1.0,'parts':{}};self.pending[key]=entry
        entry['parts'][index]=chunk;self.bytes+=len(chunk)
        if len(entry['parts'])!=count: return None
        payload=b''.join(entry['parts'][i] for i in range(count))
        self.bytes-=sum(map(len,entry['parts'].values()));del self.pending[key]
        if hashlib.sha256(payload).hexdigest()!=frame['digest']:
            self.discarded+=1;raise RejectedMessage('fragment digest mismatch')
        return decode_payload(payload)


def receive(sock, *, expected_uid, expected_pid, assembler=None,retired_pid=None):
    payload,ancillary,flags,_=sock.recvmsg(MAX_DATAGRAM+1,socket.CMSG_SPACE(HEADER.size+MAX_GROUPS*4),getattr(socket,'MSG_CMSG_CLOEXEC',0))
    credential=credentials_from_ancillary(ancillary,flags,expected_uid=expected_uid,expected_pid=expected_pid,retired_pid=retired_pid)
    # A transition may discard one explicitly known old process before JSON
    # decoding or fragment allocation. It can never admit that process as the
    # fresh producer or return its data to a mapping/ACK handler.
    if retired_pid is not None and credential.pid==retired_pid:
        raise RetiredMessage(errno.EAGAIN,'known retired producer datagram')
    # Authenticate and close unexpected descriptors before decoding or allocating.
    if assembler is None: return decode_payload(payload),credential
    reply=assembler.accept(payload,credential,time.monotonic())
    if reply is None: raise IncompleteMessage(errno.EAGAIN,'message incomplete')
    return reply,credential


def wire_datagrams(payload,*,compress=False):
    if len(payload)<=CHUNK_BYTES: return [payload]
    # Only try a moderate message: larger high-entropy answers otherwise pay
    # compression cost and still need fragmentation. Keep their existing path.
    # Level 1 is useful only when it replaces fragmentation with one datagram.
    if compress and len(payload)<=4*CHUNK_BYTES:
        packed=json.dumps({'format':'dnsalias-zlib-1','size':len(payload),
            'data':base64.b64encode(zlib.compress(payload,1)).decode('ascii')},separators=(',',':')).encode()
        if len(packed)<=CHUNK_BYTES:return [packed]
    message_id=os.urandom(16).hex();digest=hashlib.sha256(payload).hexdigest()
    count=(len(payload)+CHUNK_BYTES-1)//CHUNK_BYTES
    return [json.dumps({'format':'dnsalias-fragment-1','id':message_id,'index':i,'count':count,
                        'size':len(payload),'digest':digest,'data':base64.b64encode(payload[i*CHUNK_BYTES:(i+1)*CHUNK_BYTES]).decode('ascii')},separators=(',',':')).encode()
            for i in range(count)]


def send_observation(sock, destination, reply):
    """At most 15 bounded nonblocking datagrams; queued never means applied."""
    if sock.family!=socket.AF_UNIX or sock.type!=socket.SOCK_DGRAM or sock.getblocking():
        raise ValueError('nonblocking local datagram socket required')
    try:
        if _NATIVE_WIRE is None:payload=_encode_ack(reply)
        else:
            payload=_NATIVE_WIRE.pack_ack(reply) if type(reply) is dict and len(reply)==2 else _NATIVE_WIRE.pack(reply)
            # The native path is a single small datagram. Unsupported or
            # larger replies retain the existing grouped JSON/fragment limits.
            if payload is not None and len(payload)>CHUNK_BYTES:payload=None
        if payload is None:
            grouped = _rr_envelope(reply)
            if grouped is not None:
                item, extra = grouped
                payload=json.dumps(item,separators=(',',':'),allow_nan=False).encode()
                if len(payload)+extra>MAX_MESSAGE:
                    grouped=None
            if grouped is None:
                payload=json.dumps({'format':'dnsalias-reply-1','reply':reply},separators=(',',':'),allow_nan=False).encode()
    except (TypeError,ValueError,RecursionError): return 'invalid'
    if len(payload)>MAX_MESSAGE: return 'oversized'
    try:
        for fragment in wire_datagrams(payload,compress=True):
            if sock.sendto(fragment,destination)!=len(fragment): return 'incomplete'
        return 'queued'
    except BlockingIOError: return 'backpressure'
    except OSError as exc:
        if exc.errno==errno.EMSGSIZE: return 'socket_message_limit'
        return 'backpressure' if exc.errno in (errno.ENOBUFS,errno.EAGAIN,errno.EWOULDBLOCK) else 'unavailable'
