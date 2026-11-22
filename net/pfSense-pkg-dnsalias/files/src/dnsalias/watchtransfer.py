"""Optional startup-only transfer of one qualified empty native filter lock.

Use a separate credential-enabled local datagram endpoint. Ordinary DNS/ACK
IPC continues to reject descriptors. A fresh token binds the one-shot receiver
to an independently enrolled helper PID and inode. The caller must coordinate
watch enrollment and final qualification BEFORE publishing any confirmations.
This module installs no endpoint, hook, page or service and never retries.
"""
import array
import hashlib
import json
import os
import socket
import stat
import struct
import zlib
try:
    import fcntl
except ImportError:
    fcntl=None
from .changebarrier import FileChangeBarrier,CapabilityChangeBarrier
from .ipc import HEADER,MAX_GROUPS,RejectedMessage,parse_sockcred2,configure_sender

MAGIC=b'DAWF\x01\0\0\0'
SOURCE_MAGIC=b'DAWS\x01\0\0\0'
SOURCE_MAX_BYTES=6000
SOURCE_MAX_MANIFEST=32768
SOURCE_MAX_FDS=CapabilityChangeBarrier.MAX_FILES+CapabilityChangeBarrier.MAX_DIRECTORIES


def _token(value):
    if type(value) is not bytes or len(value)!=32 or value==b'\0'*32:
        raise ValueError('fresh nonzero 32-byte enrollment token required')
    return MAGIC+value


def _identity(value):
    if (type(value) is not tuple or len(value)!=2 or any(type(x) is not int for x in value)
        or not -(1<<63)<=value[0]<(1<<64) or not 0<value[1]<(1<<64)):
        raise ValueError('independently qualified device and inode required')
    return value


def _socket(sock):
    if not isinstance(sock,socket.socket) or sock.family!=socket.AF_UNIX or sock.type!=socket.SOCK_DGRAM:
        raise ValueError('dedicated local datagram endpoint required')


def _file(fd,identity):
    if type(fd) is not int or fd<0:raise ValueError('explicit read-only descriptor required')
    info=os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size!=0
        or (info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))!=(0,0,0o666)
        or (info.st_dev,info.st_ino)!=identity
        or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
        raise ValueError('qualified empty root-owned native lock required')


def send_filter_watch(sock,destination,fd,*,token,identity):
    """One send attempt. The caller retains its original descriptor."""
    if os.geteuid()!=0:raise ValueError('root helper required')
    _socket(sock);frame=_token(token);identity=_identity(identity);_file(fd,identity)
    if type(destination) is not str or not destination.startswith('/') or not 1<len(destination.encode())<=103:
        raise ValueError('explicit enrolled local endpoint required')
    sent=sock.sendmsg([frame],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[fd]))],socket.MSG_DONTWAIT,destination)
    if sent!=len(frame):raise RuntimeError('descriptor send outcome uncertain; do not retry')


class FilterWatchReceiver:
    """Receive at most one message; every rejected received FD is closed."""
    def __init__(self,*,helper_pid,token,identity):
        if type(helper_pid) is not int or not 0<helper_pid<2**31:
            raise ValueError('explicit enrolled helper PID required')
        self.helper_pid=helper_pid;self.frame=_token(token);self.identity=_identity(identity)
        self.state='new';self.owner=os.getpid()

    def receive(self,sock):
        if self.state!='new' or os.getpid()!=self.owner:raise ValueError('single-process one-shot enrollment required')
        _socket(sock)
        if sock.getsockopt(0,socket.LOCAL_CREDS_PERSISTENT)!=1:
            raise ValueError('persistent kernel credentials required')
        self.state='receiving';fds=[]
        try:
            payload,ancillary,flags,_=sock.recvmsg(len(self.frame)+1,
                socket.CMSG_SPACE(HEADER.size+MAX_GROUPS*4)+socket.CMSG_SPACE(array.array('i').itemsize),
                socket.MSG_DONTWAIT|getattr(socket,'MSG_CMSG_CLOEXEC',0))
            credentials=[];unexpected=False;rights=0
            for level,kind,raw in ancillary:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    values=array.array('i');complete=len(raw)-len(raw)%values.itemsize
                    values.frombytes(raw[:complete]);fds.extend(values);rights+=1
                    if complete!=len(raw):unexpected=True
                elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDS2:credentials.append(raw)
                else:unexpected=True
            # Gather every installed descriptor before a fallible operation,
            # so the finally block also closes later ancillary rights.
            for fd in fds:os.set_inheritable(fd,False)
            if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or unexpected or rights!=1 or len(fds)!=1 or len(credentials)!=1:
                raise RejectedMessage('truncated, missing or unexpected watch control data')
            parse_sockcred2(credentials[0],expected_uid=0,expected_pid=self.helper_pid)
            if payload!=self.frame:raise RejectedMessage('watch enrollment token differs')
            _file(fds[0],self.identity)
            watch=FileChangeBarrier(fds)
            self.state='enrolled';return watch
        except BaseException:
            self.state='failed';raise
        finally:
            for fd in fds:
                try:os.close(fd)
                except OSError:pass


def source_frame(entries,token):
    """Startup manifest only: the token authenticates this one enrollment."""
    _token(token)
    if type(entries) not in (list,tuple) or not 2<=len(entries)<=SOURCE_MAX_FDS:
        raise ValueError('bounded filter and source manifest required')
    manifest=[]
    for fd,kind,wanted in entries:
        if CapabilityChangeBarrier.metadata(fd,kind)!=tuple(wanted):
            raise ValueError('source metadata changed before watch transfer')
        manifest.append([kind,list(wanted)])
    encoded=json.dumps(manifest,separators=(',',':'),allow_nan=False).encode('ascii')
    if len(encoded)>SOURCE_MAX_MANIFEST:raise ValueError('source metadata exceeds startup limit')
    # One startup batch, below the deployed 8192-byte native datagram limit.
    # Compression is never used by the per-query notice poll.
    frame=SOURCE_MAGIC+token+struct.pack('!I',len(encoded))+zlib.compress(encoded)
    if len(frame)>SOURCE_MAX_BYTES:raise ValueError('source manifest exceeds startup limit')
    return frame


def send_source_watch(sock,destination,entries,*,token,restrict):
    """One root send; only event/stat capabilities leave the owner process."""
    if os.geteuid()!=0:raise ValueError('root source watch owner required')
    _socket(sock)
    if type(destination) is not str or not destination.startswith('/') or not 1<len(destination.encode())<=103:
        raise ValueError('explicit enrolled local endpoint required')
    frame=source_frame(entries,token);fds=[]
    configure_sender(sock)  # Bound this startup socket, never kernel-wide limits.
    try:
        for source,kind,wanted in entries:
            fd=restrict(source);fds.append(fd)
            if CapabilityChangeBarrier.metadata(fd,kind)!=tuple(wanted):
                raise ValueError('source changed while restricting watch capability')
        sent=sock.sendmsg([frame],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',fds))],socket.MSG_DONTWAIT,destination)
        if sent!=len(frame):raise RuntimeError('source descriptor send outcome uncertain; never retry')
        return hashlib.sha256(frame).hexdigest()
    finally:
        for fd in fds:os.close(fd)


class SourceWatchReceiver:
    """Single authenticated startup batch; ordinary DNS IPC still rejects FDs."""
    def __init__(self,*,helper_pid,token,identity,check_rights):
        if type(helper_pid) is not int or not 0<helper_pid<2**31:
            raise ValueError('explicit enrolled helper PID required')
        if not callable(check_rights):raise ValueError('native watch rights verifier required')
        self.prefix=SOURCE_MAGIC+_token(token)[len(MAGIC):]
        self.helper_pid=helper_pid;self.identity=_identity(identity);self.check_rights=check_rights
        self.owner=os.getpid();self.state='new';self.manifest_digest=None

    def receive(self,sock):
        if self.state!='new' or os.getpid()!=self.owner:raise ValueError('single-process one-shot enrollment required')
        _socket(sock)
        if sock.getsockopt(0,socket.LOCAL_CREDS_PERSISTENT)!=1 or not hasattr(socket,'MSG_CMSG_CLOEXEC'):
            raise ValueError('persistent credentials and atomic close-on-exec receive required')
        self.state='receiving';fds=[]
        try:
            frame,controls,flags,_=sock.recvmsg(SOURCE_MAX_BYTES+1,
                socket.CMSG_SPACE(HEADER.size+MAX_GROUPS*4)+socket.CMSG_SPACE(SOURCE_MAX_FDS*array.array('i').itemsize),
                socket.MSG_DONTWAIT|socket.MSG_CMSG_CLOEXEC)
            credentials=[];rights=0;unexpected=False
            for level,kind,raw in controls:
                if level==socket.SOL_SOCKET and kind==socket.SCM_RIGHTS:
                    values=array.array('i');complete=len(raw)-len(raw)%values.itemsize
                    values.frombytes(raw[:complete]);fds.extend(values);rights+=1
                    if complete!=len(raw):unexpected=True
                elif level==socket.SOL_SOCKET and kind==socket.SCM_CREDS2:credentials.append(raw)
                else:unexpected=True
            if (flags&~(socket.MSG_CMSG_CLOEXEC|socket.MSG_DONTWAIT) or unexpected or rights!=1 or len(credentials)!=1
                or not 2<=len(fds)<=SOURCE_MAX_FDS or not len(self.prefix)<len(frame)<=SOURCE_MAX_BYTES):
                raise RejectedMessage('source watch batch differs: flags=%d controls=%d/%d fds=%d bytes=%d unexpected=%s'
                    %(flags,rights,len(credentials),len(fds),len(frame),unexpected))
            parse_sockcred2(credentials[0],expected_uid=0,expected_pid=self.helper_pid)
            if not frame.startswith(self.prefix):raise RejectedMessage('source watch enrollment token differs')
            body=frame[len(self.prefix):]
            if len(body)<5:raise RejectedMessage('short source metadata frame')
            expected=struct.unpack('!I',body[:4])[0]
            if not 1<=expected<=SOURCE_MAX_MANIFEST:raise RejectedMessage('source metadata expansion limit')
            decoder=zlib.decompressobj()
            try:decoded=decoder.decompress(body[4:],SOURCE_MAX_MANIFEST+1)
            except zlib.error as exc:raise RejectedMessage('invalid compressed source manifest') from exc
            if len(decoded)!=expected or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
                raise RejectedMessage('source metadata length or stream differs')
            manifest=json.loads(decoded)
            if type(manifest) is not list or len(manifest)!=len(fds):raise RejectedMessage('source manifest count differs')
            entries=[]
            for fd,item in zip(fds,manifest):
                if (type(item) is not list or len(item)!=2 or type(item[0]) is not str
                    or item[0] not in ('file','directory') or type(item[1]) is not list
                    or len(item[1])!=(9 if item[0]=='file' else 5) or any(type(n) is not int for n in item[1])):
                    raise RejectedMessage('source manifest metadata malformed')
                if os.get_inheritable(fd) or self.check_rights(fd) is not True:
                    raise RejectedMessage('received descriptor grants rights beyond watch and stat')
                entries.append((fd,item[0],tuple(item[1])))
            _,kind,lock=entries[0]
            if kind!='file' or lock[:2]!=self.identity or lock[2:7]!=(0,0,0o666,1,0):
                raise RejectedMessage('independently enrolled native filter lock differs')
            watch=CapabilityChangeBarrier(entries,check_rights=self.check_rights)
            self.manifest_digest=hashlib.sha256(frame).hexdigest();self.state='enrolled';return watch
        except BaseException:
            self.state='failed';raise
        finally:
            for fd in fds:
                try:os.close(fd)
                except OSError:pass
