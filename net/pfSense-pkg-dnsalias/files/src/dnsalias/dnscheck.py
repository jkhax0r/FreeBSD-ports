"""Bounded loopback DNS behavior checks for explicit controlled-load trials.

Read-only probes, outside callbacks. Results compare answer behavior while
ignoring changing TTLs; they are NEVER lease inputs, policy decisions, proof of
all resolver behavior, or proof of the exact loaded Python source. The caller
qualifies the resolver lifetime and coordinates its trial separately.
"""
import math
import re
import secrets
import socket
import struct


MAX_BYTES=4096


def _question(name,kind):
    if type(name) is not str or not 1<=len(name)<=254 or type(kind) is not int or kind not in (1,28):
        raise ValueError('bounded explicit A or AAAA probe required')
    name=name.lower().removesuffix('.')
    if not 1<=len(name)<=253:raise ValueError('bounded DNS name required')
    labels=name.split('.')
    if any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?',label) for label in labels):
        raise ValueError('explicit ASCII DNS name required')
    return name+'.',b''.join(bytes([len(label)])+label.encode('ascii') for label in labels)+b'\0'+struct.pack('!HH',kind,1)


def _name(raw,start):
    pos=start;resume=None;labels=[];visited=set();wire_length=1
    for _ in range(128):
        if pos>=len(raw) or pos in visited:raise ValueError('truncated or cyclic DNS name')
        visited.add(pos);length=raw[pos];pos+=1
        if length==0:return '.'.join(labels)+'.',pos if resume is None else resume
        if length&0xc0==0xc0:
            if pos>=len(raw) or len(visited)>64:raise ValueError('bounded DNS compression required')
            pointer=((length&0x3f)<<8)|raw[pos]
            if resume is None:resume=pos+1
            pos=pointer;continue
        if length>63 or pos+length>len(raw):raise ValueError('invalid DNS label')
        label=raw[pos:pos+length].decode('ascii').lower()
        if not re.fullmatch(r'[a-z0-9_-]+',label):raise ValueError('unsupported DNS label')
        labels.append(label);wire_length+=length+1
        if wire_length>255:raise ValueError('DNS name exceeds bound')
        pos+=length
    raise ValueError('DNS name traversal exceeds bound')


def parse(raw,*,ident,name,kind):
    name,_=_question(name,kind)
    if type(ident) is not int or not 0<=ident<=65535 or type(raw) is not bytes or not 12<=len(raw)<=MAX_BYTES:
        raise ValueError('bounded DNS reply and query identity required')
    received,flags,qd,an,ns,ar=struct.unpack('!6H',raw[:12])
    if received!=ident or not flags&0x8000 or flags&0x7a40 or qd!=1 or an+ns+ar>128:
        raise ValueError('mismatched, truncated or unsupported DNS response')
    question,pos=_name(raw,12)
    if pos+4>len(raw) or question!=name or struct.unpack('!HH',raw[pos:pos+4])!=(kind,1):
        raise ValueError('DNS question mismatch')
    pos+=4;answers=[]
    for index in range(an+ns+ar):
        owner,pos=_name(raw,pos)
        if pos+10>len(raw):raise ValueError('truncated DNS record header')
        record_kind,klass,ttl,size=struct.unpack('!HHIH',raw[pos:pos+10]);pos+=10;end=pos+size
        if end>len(raw):raise ValueError('truncated DNS record data')
        if record_kind==41 and ttl&0xffff0000:raise ValueError('extended DNS error or unsupported EDNS version')
        if index<an:
            if klass!=1 or record_kind not in (1,5,28):raise ValueError('unsupported probe answer')
            if record_kind==5:
                value,used=_name(raw,pos)
                if used!=end:raise ValueError('CNAME length mismatch')
            else:
                if size!=(4 if record_kind==1 else 16):raise ValueError('invalid address record length')
                value=socket.inet_ntop(socket.AF_INET if record_kind==1 else socket.AF_INET6,raw[pos:end])
            answers.append((owner,record_kind,value))
        pos=end
    if pos!=len(raw):raise ValueError('unexpected trailing DNS data')
    return {'rcode':flags&15,'answers':[{'name':owner,'type':record_kind,'value':value}
        for owner,record_kind,value in sorted(set(answers))],'ttl_comparison':'ignored; never a lease source'}


def query(name,*,kind=1,address='127.0.0.1',port,timeout_seconds=.5):
    canonical,question=_question(name,kind)
    if address not in ('127.0.0.1','::1') or type(port) is not int or not 1<=port<=65535:
        raise ValueError('explicit literal loopback DNS endpoint required')
    if type(timeout_seconds) not in (int,float) or not math.isfinite(timeout_seconds) or not 0<timeout_seconds<=1:
        raise ValueError('bounded DNS probe timeout required')
    ident=secrets.randbelow(65536);packet=struct.pack('!6H',ident,0x100,1,0,0,0)+question
    with socket.socket(socket.AF_INET6 if address=='::1' else socket.AF_INET,socket.SOCK_DGRAM) as client:
        client.settimeout(timeout_seconds);client.connect((address,port));client.send(packet)
        reply=client.recv(MAX_BYTES+1)
    return parse(reply,ident=ident,name=canonical,kind=kind)
