"""Inactive owned FreeBSD reply socket; no default live path or stale cleanup.

Caller provisions and supervises the private directory and its ancestors. This
class never creates/deletes directories or replaces existing paths. Native
credentials remain mandatory; filesystem permissions alone do not authenticate
the producer. Socket replacement or directory drift permanently ends ownership.
"""
import os
import re
from pathlib import Path
import socket
import stat

from .ipc import configure_receiver

NAME='replies.sock'
MAX_ACK_SOCKETS=16


def ack_socket_names(count):
    if type(count) is not int or not 1<=count<=MAX_ACK_SOCKETS:
        raise ValueError('bounded ACK socket count required')
    return (NAME,*(f'w{slot:x}.sock' for slot in range(1,count)))


class EndpointChanged(ValueError): pass


class ReplyEndpoint:
    def __init__(self,directory,*,expected_uid=None,expected_gid=None,group_sender=False,name=NAME):
        if os.name!='posix' or not all(hasattr(os,n) for n in ('O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC','geteuid','getegid')):
            raise RuntimeError('qualified POSIX endpoint ownership required')
        if name not in ack_socket_names(MAX_ACK_SOCKETS):raise ValueError('fixed ACK socket name required')
        self.name=name;self.directory=Path(directory);self.path=self.directory/name
        self.uid=os.geteuid() if expected_uid is None else expected_uid
        self.gid=os.getegid() if expected_gid is None else expected_gid
        if (not self.directory.is_absolute() or '..' in self.directory.parts or len(os.fsencode(self.path))>103
            or type(self.uid) is not int or self.uid!=os.geteuid()
            or type(self.gid) is not int or not 0<=self.gid<2**32 or type(group_sender) is not bool):
            raise ValueError('explicit short absolute owned socket directory required')
        self.mode=0o620 if group_sender else 0o600
        self.directory_mode=0o750 if group_sender else 0o700
        self.fd=None;self.socket=None;self.directory_identity=None;self.socket_identity=None
        self.state='opening';self.reason=None;self.cleanup=None;self.failure_detail=None
        try:
            self.fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.directory_identity=self._directory()
            # Existing sockets, files and symlinks all require explicit review.
            try: os.stat(self.name,dir_fd=self.fd,follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise FileExistsError('reply endpoint already exists; never unlink automatically')
            self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM)
            configure_receiver(self.socket)
            self.socket.bind(str(self.path))
            self._directory()
            created=os.stat(self.name,dir_fd=self.fd,follow_symlinks=False)
            if not stat.S_ISSOCK(created.st_mode) or created.st_uid!=self.uid or created.st_nlink!=1:
                raise EndpointChanged('created socket ownership unqualified')
            self.socket_identity=(created.st_dev,created.st_ino)
            os.chown(self.name,-1,self.gid,dir_fd=self.fd,follow_symlinks=False)
            os.chmod(self.name,self.mode,dir_fd=self.fd,follow_symlinks=False)
            self._socket();self.state='open'
        except Exception:
            # A partially completed bind is not retried or automatically erased.
            self.reason='open_failed';self.close(remove=False);raise

    def _directory(self):
        if self.fd is None: raise EndpointChanged('directory descriptor closed')
        opened=os.fstat(self.fd);named=os.stat(self.directory,follow_symlinks=False)
        for item in (opened,named):
            if not stat.S_ISDIR(item.st_mode) or item.st_uid!=self.uid or item.st_gid!=self.gid or stat.S_IMODE(item.st_mode)!=self.directory_mode:
                raise EndpointChanged('directory owner, group, mode or type changed')
        identity=(opened.st_dev,opened.st_ino)
        if identity!=(named.st_dev,named.st_ino) or self.directory_identity not in (None,identity):
            raise EndpointChanged('directory replaced')
        return identity

    def _socket(self):
        self._directory()
        self._check_socket()

    def _check_socket(self):
        item=os.stat(self.name,dir_fd=self.fd,follow_symlinks=False)
        if (not stat.S_ISSOCK(item.st_mode) or item.st_uid!=self.uid or item.st_gid!=self.gid
            or stat.S_IMODE(item.st_mode)!=self.mode or item.st_nlink!=1
            or (item.st_dev,item.st_ino)!=self.socket_identity):
            raise EndpointChanged('socket owner, type, mode, links or inode changed')

    def healthy(self):
        if self.state!='open': return False
        if self.socket is None or self.socket.fileno()<0:
            self.reason='endpoint_socket_closed';self.close(remove=False);return False
        try: self._socket();return True
        except (OSError,EndpointChanged) as exc:
            self.failure_detail=(type(exc).__name__+(': '+str(exc)[:160] if isinstance(exc,EndpointChanged) else ' errno='+str(exc.errno)))
            self.reason='endpoint_ownership_changed';self.close(remove=False);return False

    def close(self,*,remove=True):
        if self.cleanup is not None: return dict(self.cleanup)
        removed=False;reason=self.reason or 'caller_closed'
        if remove and self.state=='open':
            try:
                self._socket()
                # Directory is not writable by the sender group. The caller
                # must coordinate other processes with the same owner/root.
                os.unlink(self.name,dir_fd=self.fd);removed=True
            except FileNotFoundError: reason='endpoint_missing'
            except (OSError,EndpointChanged): reason='endpoint_ownership_changed'
        if self.socket is not None:
            self.socket.close();self.socket=None
        if self.fd is not None:
            os.close(self.fd);self.fd=None
        self.state='closed';self.reason=reason
        self.cleanup={'socket_closed':True,'owned_path_removed':removed,'reason':reason}
        return dict(self.cleanup)

    def status(self):
        return {'state':self.state,'reason':self.reason,'path':str(self.path),
                'uid':self.uid,'gid':self.gid,'mode':oct(self.mode),'cleanup':self.cleanup,
                'failure_detail':self.failure_detail}

    def __enter__(self): return self
    def __exit__(self,*args): self.close()


class GenerationReplyEndpoint:
    """One exclusive ACK directory for a new resolver generation.

    The caller provisions/supervises the parent. Old generation paths are never
    adopted or deleted here, including after a producer crash. Creation and
    normal close touch only this object's exact directory/socket identities.
    """
    MAX_GENERATIONS=32

    def __init__(self,parent,*,generation,native_check=None,socket_count=1):
        if native_check is not None and not callable(native_check):raise ValueError('qualified native checker required')
        self.native_check=native_check
        self.parent=Path(parent);self.uid=os.geteuid();self.gid=os.getegid()
        if (type(generation) is not str or not re.fullmatch('[a-f0-9]{32}',generation)
            or not self.parent.is_absolute() or '..' in self.parent.parts):
            raise ValueError('canonical ACK parent and generation required')
        self.name='g-'+generation;self.directory=self.parent/self.name;self.path=self.directory/NAME
        if len(os.fsencode(self.path))>103:raise ValueError('generation ACK path exceeds native limit')
        self.parent_fd=self.directory_fd=None;self.parent_identity=self.directory_identity=None
        self.names=ack_socket_names(socket_count);self.endpoints=[]
        self.cleanup=None;self.created=False;self.state='creating'
        try:
            self.parent_fd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.parent_identity=self._pin(self.parent_fd,self.parent)
            # Bounded namespace growth, without inspecting/adopting old sockets.
            count=0
            with os.scandir(self.parent_fd) as entries:
                for unused in entries:
                    count+=1
                    if count>=self.MAX_GENERATIONS:raise ValueError('ACK generation namespace needs explicit cleanup')
            os.mkdir(self.name,0o700,dir_fd=self.parent_fd);self.created=True
            self.directory_fd=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent_fd)
            self.directory_identity=self._pin(self.directory_fd,self.directory)
            for name in self.names:
                self.endpoints.append(ReplyEndpoint(self.directory,expected_uid=self.uid,expected_gid=self.gid,name=name))
            self.state='open'
        except Exception:
            self.close(remove=False);raise

    def _pin(self,fd,path):
        opened=os.fstat(fd);named=os.stat(path,follow_symlinks=False)
        def metadata(i):
            if (not stat.S_ISDIR(i.st_mode) or (i.st_uid,i.st_gid,stat.S_IMODE(i.st_mode))!=(self.uid,self.gid,0o700)):
                raise EndpointChanged('generation ACK directory ownership changed')
            return i.st_dev,i.st_ino,i.st_uid,i.st_gid,stat.S_IMODE(i.st_mode)
        if metadata(opened)!=metadata(named):raise EndpointChanged('generation ACK directory replaced')
        return metadata(opened)

    def _check(self):
        if self._pin(self.parent_fd,self.parent)!=self.parent_identity:raise EndpointChanged('ACK parent replaced')
        if self._pin(self.directory_fd,self.directory)!=self.directory_identity:raise EndpointChanged('ACK generation replaced')

    @property
    def endpoint(self):return self.endpoints[0] if self.endpoints else None

    @property
    def socket(self):return None if self.endpoint is None else self.endpoint.socket

    def healthy(self,slot=0):
        if self.state!='open':return False
        try:
            if (self.native_check is not None and self.endpoint is not None and self.endpoint.state=='open'
                and self.endpoint.socket is not None and self.endpoint.socket.fileno()>=0):
                if self.native_check(self.parent_fd,str(self.parent),self.directory_fd,str(self.directory),
                    self.endpoint.fd,self.uid,self.gid,self.parent_identity,self.directory_identity,
                    self.endpoint.directory_identity,self.endpoint.socket_identity):
                    if not slot:return True
                else:
                    # Failed native validation cannot become a successful fallback.
                    self.endpoint.healthy()
                    raise EndpointChanged('native generation ACK ownership changed')
            else:
                self._check()
                if not self.endpoint.healthy():raise EndpointChanged('generation ACK endpoint changed')
            if slot:
                endpoint=self.endpoints[slot]
                if endpoint.state!='open' or endpoint.socket is None or endpoint.socket.fileno()<0:
                    raise EndpointChanged('worker ACK endpoint closed')
                endpoint._check_socket()
            return True
        except (OSError,ValueError):self.state='uncertain';return False

    def close(self,*,remove=True):
        if self.cleanup is not None:return dict(self.cleanup)
        removed=False;reason=None;uncertain=False
        try:
            if not remove or self.state!='open':raise EndpointChanged('generation ACK ownership requires inspection')
            self._check()
            if set(os.listdir(self.directory_fd))!=set(self.names):raise EndpointChanged('unexpected generation ACK content')
            for endpoint in self.endpoints:endpoint._socket()
            for endpoint in self.endpoints:
                if not endpoint.close()['owned_path_removed']:raise EndpointChanged('ACK socket removal not verified')
            self._check()
            if os.listdir(self.directory_fd):raise EndpointChanged('generation ACK content appeared')
            os.rmdir(self.name,dir_fd=self.parent_fd);removed=True;os.fsync(self.parent_fd)
        except (OSError,ValueError) as exc:reason=type(exc).__name__;uncertain=True
        finally:
            for endpoint in self.endpoints:endpoint.close(remove=False)
            for name in ('directory_fd','parent_fd'):
                fd=getattr(self,name)
                if fd is not None:os.close(fd);setattr(self,name,None)
            self.state='closed'
        self.cleanup={'owned_directory_removed':removed,'inspection_required':self.created and (not removed or uncertain),'reason':reason}
        return dict(self.cleanup)

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
