"""Explicit owned directory/socket for one temporary observation trial.

No default paths, stale adoption, recursive deletion, hook or configuration
changes. Caller must keep this alive until the receiver releases its resources
and independently verify trial restoration before removing installation/data.
Crash leftovers require inspection; a marker alone never authorizes adoption.
"""
import json
import os
from pathlib import Path
import re
import stat
import sys

from .replyendpoint import ReplyEndpoint,NAME
from .sourceaudit import _path


class TrialEndpoint:
    MARKER='OWNER.json'

    def __init__(self,parent,*,trial_id,sender_uid,sender_gid):
        if not sys.platform.startswith('freebsd'):raise ValueError('qualified native endpoint ownership required')
        parts=_path(str(parent))
        if type(trial_id) is not str or not re.fullmatch('[a-f0-9]{32}',trial_id):raise ValueError('explicit trial identity required')
        if any(type(value) is not int or not 0<=value<2**32 for value in (sender_uid,sender_gid)):
            raise ValueError('explicit sender owner/group required')
        self.uid=os.geteuid();self.gid=sender_gid;self.allowed_uids={0,self.uid,sender_uid}
        self.parent=Path(parent);self.name='da-'+trial_id;self.directory=self.parent/self.name
        if len(os.fsencode(self.directory/NAME))>103:raise ValueError('owned endpoint path exceeds native limit')
        self.parents=[];self.fds=[];self.directory_fd=None;self.directory_identity=None
        self.marker_fd=None;self.marker_identity=None;self.endpoint=None;self.cleanup=None
        self.marker=json.dumps({'format':'dnsalias-owned-reply-endpoint-1','trial_id':trial_id,
            'parent':str(self.parent),'uid':self.uid,'gid':self.gid},sort_keys=True,separators=(',',':')).encode()
        self.state='creating'
        try:
            parent_fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);self.fds.append(parent_fd)
            self.parents.append((None,'/',parent_fd,self._parent_metadata(os.fstat(parent_fd))))
            for name in parts:
                fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd);self.fds.append(fd)
                self.parents.append((parent_fd,name,fd,self._parent_metadata(os.fstat(fd))));parent_fd=fd
            self.parent_fd=parent_fd;self._parents()
            # Existing directories, symlinks and partial trials all stay intact.
            os.mkdir(self.name,0o700,dir_fd=parent_fd)
            fd=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent_fd)
            self.directory_fd=fd;self.fds.append(fd)
            os.fchown(fd,self.uid,self.gid);os.fchmod(fd,0o750)
            self.directory_identity=self._directory()
            self.marker_fd=os.open(self.MARKER,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
            self.fds.append(self.marker_fd)
            if os.write(self.marker_fd,self.marker)!=len(self.marker):raise OSError('incomplete ownership marker write')
            os.fsync(self.marker_fd);self.marker_identity=self._marker()
            os.fsync(fd);os.fsync(parent_fd);self._parents()
            self.endpoint=ReplyEndpoint(self.directory,expected_uid=self.uid,expected_gid=self.gid,group_sender=True)
            self.state='open'
        except Exception:
            # A failed bind/create is visible but not automatically erased.
            if self.endpoint is not None:self.endpoint.close(remove=False)
            self._release();self.state='uncertain';raise

    def _parent_metadata(self,item):
        mode=stat.S_IMODE(item.st_mode)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid not in self.allowed_uids or mode&0o6000
            or mode&0o022 and not (item.st_uid==0 and mode&stat.S_ISVTX)):
            raise ValueError('endpoint ancestor ownership or mode changed')
        return item.st_dev,item.st_ino,item.st_uid,item.st_gid,mode

    def _parents(self):
        for parent,name,fd,wanted in self.parents:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat('/',follow_symlinks=False)
            if self._parent_metadata(os.fstat(fd))!=wanted or self._parent_metadata(named)!=wanted:
                raise ValueError('endpoint ancestor replaced')

    def _directory(self):
        self._parents();opened=os.fstat(self.directory_fd);named=os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False)
        for item in (opened,named):
            if not stat.S_ISDIR(item.st_mode) or (item.st_uid,item.st_gid,stat.S_IMODE(item.st_mode))!=(self.uid,self.gid,0o750):
                raise ValueError('owned endpoint directory changed')
        identity=opened.st_dev,opened.st_ino
        if identity!=(named.st_dev,named.st_ino) or self.directory_identity not in (None,identity):raise ValueError('endpoint directory replaced')
        return identity

    def _marker(self):
        self._directory();opened=os.fstat(self.marker_fd);named=os.stat(self.MARKER,dir_fd=self.directory_fd,follow_symlinks=False)
        for item in (opened,named):
            if (not stat.S_ISREG(item.st_mode) or item.st_uid!=self.uid or stat.S_IMODE(item.st_mode)!=0o600
                or item.st_nlink!=1 or item.st_size!=len(self.marker)):
                raise ValueError('endpoint ownership marker changed')
        identity=opened.st_dev,opened.st_ino
        if identity!=(named.st_dev,named.st_ino) or self.marker_identity not in (None,identity):raise ValueError('endpoint marker replaced')
        if os.pread(self.marker_fd,len(self.marker)+1,0)!=self.marker:raise ValueError('endpoint marker content changed')
        return identity

    def _release(self):
        for fd in reversed(self.fds):os.close(fd)
        self.fds=[]

    def healthy(self):
        if self.state!='open':return False
        try:
            self._marker()
            if not self.endpoint.healthy():raise ValueError('endpoint socket changed')
            return True
        except (OSError,ValueError):self.state='uncertain';return False

    def close(self):
        if self.cleanup is not None:return dict(self.cleanup)
        removed=False;reason=None
        try:
            if self.state!='open':raise ValueError('endpoint ownership already uncertain')
            self._marker()
            if set(os.listdir(self.directory_fd)) not in ({self.MARKER,NAME},{self.MARKER}):
                raise ValueError('unexpected endpoint directory content')
            result=self.endpoint.close()
            if not result['owned_path_removed']:raise ValueError('owned socket removal not verified')
            self._marker()
            if set(os.listdir(self.directory_fd))!={self.MARKER}:raise ValueError('endpoint directory content changed')
            os.unlink(self.MARKER,dir_fd=self.directory_fd);os.fsync(self.directory_fd)
            self._directory();os.rmdir(self.name,dir_fd=self.parent_fd);os.fsync(self.parent_fd);removed=True
        except (OSError,ValueError) as exc:reason=type(exc).__name__
        finally:
            if self.endpoint is not None and self.endpoint.state=='open':self.endpoint.close(remove=False)
            self._release();self.state='closed'
        self.cleanup={'owned_directory_removed':removed,'inspection_required':not removed,'reason':reason}
        return dict(self.cleanup)

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
