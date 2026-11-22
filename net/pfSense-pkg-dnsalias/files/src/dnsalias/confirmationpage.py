"""Startup-only ownership of one mutable native confirmation page.

The code library stays in SourceAudit. This file intentionally has no content
hash: the enrolled root publisher changes its atomics. Pinned directory/file
identities, exact native header/token and separate process watches establish
its ownership. No lookup opens files. No existing page is adopted or repaired.

This does not enroll the service, resolver, filter reload or cleanup worker.
Every independent PF mutator must fence its enrolled page before mutation.
"""
import os
from pathlib import Path
import re
import stat


PAGE_SIZE=196736
PAGE_ABI=3
FIELDS=frozenset(('path','device','inode','uid','gid','mode','size','parent','token','writer_pid','page_abi'))


def _directory(info):
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),stat.S_IFMT(info.st_mode))


def _parents(path,allowed):
    result=[]
    for parent in reversed(Path(path).parents):
        info=parent.lstat();mode=stat.S_IMODE(info.st_mode)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in allowed or mode&0o6000
            or mode&0o022 and not (info.st_uid==0 and mode&stat.S_ISVTX)):
            raise ValueError('confirmation ancestor ownership changed')
        result.append((str(parent),_directory(info)))
    return result


def contract(value):
    if type(value) is not dict or value.keys()!=FIELDS:raise ValueError('complete confirmation identity required')
    path=value['path']
    if (type(path) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,511}',path)
        or any(p in ('','.','..') for p in path.split('/')[1:])
        or Path(path).name!='confirmation.page'):
        raise ValueError('canonical confirmation page path required')
    keys=('device','inode','uid','gid','mode','size','writer_pid','page_abi')
    if (any(type(value[k]) is not int for k in keys)
        or not -(1<<63)<=value['device']<(1<<64) or not 0<value['inode']<(1<<64)
        or (value['uid'],value['gid'],value['mode'],value['size'],value['page_abi'])!=(0,0,0o444,PAGE_SIZE,PAGE_ABI)
        or not 0<value['writer_pid']<(1<<31)
        or type(value['token']) is not str or not re.fullmatch('[a-f0-9]{64}',value['token'])
        or value['token']=='0'*64):raise ValueError('root-owned fixed-layout confirmation required')
    parent=value['parent']
    if (type(parent) not in (tuple,list) or len(parent)!=6 or any(type(v) is not int for v in parent)
        or not -(1<<63)<=parent[0]<(1<<64) or not 0<parent[1]<(1<<64)
        or parent[2]!=0 or not 0<=parent[3]<(1<<32) or parent[4] not in (0o700,0o750)
        or parent[5]!=stat.S_IFDIR):raise ValueError('captured root-owned parent required')
    return dict(value,parent=tuple(parent))


def _file(info,value):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
        or (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_size)
        !=(value['device'],value['inode'],0,0,0o444,PAGE_SIZE)):
        raise ValueError('confirmation page identity changed')


def _directory_check(parent,path,expected):
    if _directory(os.fstat(parent))!=expected or _directory(Path(path).parent.lstat())!=expected:
        raise ValueError('confirmation parent identity changed')


class ConfirmationPage:
    """Own a new page; close fences it, retire also removes the exact file."""
    @classmethod
    def create(cls,native,directory,*,expected_directory,ancestor_uids=(0,)):
        if os.geteuid()!=0:raise ValueError('root publisher required')
        if native.PAGE_SIZE!=PAGE_SIZE or native.PAGE_ABI!=PAGE_ABI:raise ValueError('qualified native layout required')
        directory=Path(directory);path=directory/'confirmation.page'
        # Validate the fixed descriptor before creating anything.
        token=os.urandom(32)
        value=contract({'path':str(path),'device':0,'inode':1,'uid':0,'gid':0,'mode':0o444,
                        'size':PAGE_SIZE,'page_abi':PAGE_ABI,'writer_pid':os.getpid(),
                        'parent':expected_directory,'token':token.hex()})
        parents=_parents(path,ancestor_uids)
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fd=None;handle=None;created=None
        try:
            _directory_check(parent,path,value['parent'])
            if _parents(path,ancestor_uids)!=parents:raise ValueError('confirmation ancestor changed before creation')
            fd=os.open(path.name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444,dir_fd=parent)
            os.fchown(fd,0,0);os.fchmod(fd,0o444);os.ftruncate(fd,PAGE_SIZE)
            info=os.fstat(fd);created=(info.st_dev,info.st_ino)
            value=contract(value|{'device':info.st_dev,'inode':info.st_ino})
            _file(info,value)
            handle=native.create_writer(fd,token)
            self=cls();self.native=native;self.handle=handle;self.value=value;self.path=path
            self.parent=parent;self.fd=fd;self.creator=os.getpid();self.parents=parents
            self.ancestor_uids=tuple(ancestor_uids);self.closed=False;self.retired=False
            self.audit();return self
        except BaseException:
            if handle is not None:native.close(handle)
            try:
                if created is not None:
                    _directory_check(parent,path,value['parent'])
                    _file(os.stat(path.name,dir_fd=parent,follow_symlinks=False),value)
                    os.unlink(path.name,dir_fd=parent)
            finally:
                if fd is not None:os.close(fd)
                os.close(parent)
            raise

    def _owner(self):
        if os.geteuid()!=0 or os.getpid()!=self.creator or self.retired:
            raise ValueError('live same-process page owner required')

    def descriptor(self,*,chroot=''):
        self._owner();self.audit();value=dict(self.value)
        if chroot:value['path']=str(Path('/')/self.path.relative_to(chroot))
        return contract(value)

    def audit(self):
        self._owner();_directory_check(self.parent,self.path,self.value['parent'])
        if _parents(self.path,self.ancestor_uids)!=self.parents:raise ValueError('confirmation ancestor changed')
        _file(os.fstat(self.fd),self.value)
        _file(os.stat(self.path.name,dir_fd=self.parent,follow_symlinks=False),self.value)

    def close(self):
        self._owner()
        if not self.closed:self.native.close(self.handle);self.closed=True

    def retire(self):
        self.close()  # A failed ownership check must still leave our old page fenced.
        try:
            self.audit();os.unlink(self.path.name,dir_fd=self.parent)
        finally:
            os.close(self.fd);os.close(self.parent);self.retired=True


class ConfirmationMapping:
    """Read-only reader or root fence-only capability enrolled at startup."""
    @classmethod
    def open(cls,native,value,*,role,ancestor_uids=None):
        if role not in ('reader','revoker'):raise ValueError('explicit reader/revoker role required')
        value=contract(value);path=Path(value['path'])
        if role=='revoker' and os.geteuid()!=0:raise ValueError('root revoker required')
        allowed=(0,os.geteuid()) if ancestor_uids is None else tuple(ancestor_uids)
        parents=_parents(path,allowed)
        parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        fd=None;handle=None
        try:
            _directory_check(parent,path,value['parent'])
            fd=os.open(path.name,(os.O_RDONLY if role=='reader' else os.O_RDWR)|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
            _file(os.fstat(fd),value);_file(os.stat(path.name,dir_fd=parent,follow_symlinks=False),value)
            handle=getattr(native,'open_'+role)(fd,bytes.fromhex(value['token']),value['writer_pid'])
            _directory_check(parent,path,value['parent'])
            _file(os.fstat(fd),value);_file(os.stat(path.name,dir_fd=parent,follow_symlinks=False),value)
            if _parents(path,allowed)!=parents:raise ValueError('confirmation ancestor changed during enrollment')
            self=cls();self.native=native;self.handle=handle;self.role=role
            self.creator=os.getpid();self.closed=False;return self
        except BaseException:
            if handle is not None:native.close(handle)
            raise
        finally:
            if fd is not None:os.close(fd)
            os.close(parent)

    def fence(self):
        if self.closed or self.creator!=os.getpid() or self.role!='revoker':raise ValueError('live revoker required')
        return self.native.fence(self.handle)

    def close(self):
        if self.creator!=os.getpid():raise ValueError('same-process mapping required')
        if not self.closed:self.native.close(self.handle);self.closed=True
