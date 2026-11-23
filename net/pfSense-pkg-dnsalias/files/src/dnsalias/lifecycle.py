"""Native source lifetime coordination and pre-import service entry point.

Workers hold a shared lifetime lock. Source replacement/removal holds it
exclusively. Short controls also serialize with one another. Locks are
nonblocking, close on exec, and live beside retained data so source/data
removal never replaces a lock inode. No timers, recovery or DNS/PF actions.

This module intentionally imports only the standard library: the executable
entry acquires the lifetime guard before importing any other package module.
An empty coordination inode survives uninstall alongside retained statistics.
"""
import contextvars
import functools
import inspect
import json
import os
from pathlib import Path
import re
import runpy
import stat
import sys
import threading
try:
    import fcntl
except ImportError:
    fcntl=None

OWNER='dnsalias-observation-v1'
_active=contextvars.ContextVar('dnsalias_source_lifetimes',default={})


class LifecycleBusy(RuntimeError):pass


def process_command(pid, *, timeout=1):
    """Read a FreeBSD process command, returning None only for a reaped PID."""
    import subprocess
    if type(pid) is not int or pid<=1:raise ValueError('recorded process identity required')
    result=subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','command='],
                          capture_output=True,text=True,timeout=timeout)
    if result.returncode==1 and not result.stdout and not result.stderr:return None
    if result.returncode!=0 or result.stderr or not result.stdout.strip() or len(result.stdout)>16384:
        raise ValueError('prior process status unavailable; inspect before recovery')
    return result.stdout.strip()


def canonical(path):
    path=Path(path)
    if not path.is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,511}',str(path)) or '..' in path.parts:
        raise ValueError('canonical absolute source/data paths required')
    return path


def _directory(path):
    info=path.lstat();mode=stat.S_IMODE(info.st_mode);sticky=info.st_uid==0 and bool(mode&stat.S_ISVTX)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.geteuid()) or mode&0o6000 or mode&0o022 and not sticky:
        raise ValueError('source lifecycle parent ownership changed')
    return info.st_dev,info.st_ino,info.st_uid,info.st_gid,mode


def _parents(path):return [(parent,_directory(parent)) for parent in reversed((path,*path.parents))]


def _same_parents(parents):
    if any(_directory(path)!=identity for path,identity in parents):raise ValueError('source lifecycle parent replaced')


def _json(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);named=path.lstat()
        fields=lambda i:(i.st_dev,i.st_ino,i.st_uid,i.st_gid,i.st_mode,i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns)
        if (fields(before)!=fields(named) or not stat.S_ISREG(before.st_mode) or before.st_uid!=os.geteuid()
            or stat.S_IMODE(before.st_mode)!=0o600 or before.st_nlink!=1 or not 0<before.st_size<=limit):raise ValueError('owned lifecycle authority changed')
        raw=os.pread(fd,limit+1,0)
        if len(raw)!=before.st_size or fields(before)!=fields(os.fstat(fd)) or fields(before)!=fields(path.lstat()):raise ValueError('lifecycle authority changed during read')
    finally:os.close(fd)
    return json.loads(raw)


def authority(root,data):
    parents=_parents(root)+_parents(data)
    if any(stat.S_IMODE(path.stat().st_mode)!=0o700 or path.stat().st_uid!=os.geteuid() for path in (root,data)):
        raise ValueError('private owned source and data directories required')
    if _json(data/'OWNER.json',4096)!={'owner':OWNER,'root':str(root)}:raise ValueError('source lifetime owner differs')
    manifest=_json(root/'MANIFEST.json',1024*1024)
    if type(manifest) is not dict or manifest.get('format')!=1 or manifest.get('owner')!=OWNER:raise ValueError('owned source manifest required')
    _same_parents(parents)


class _Lock:
    def __init__(self,path,mode):
        self.path=path;self.fd=None;self.parents=_parents(path.parent)
        try:
            try:
                self.fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                os.fchmod(self.fd,0o600);os.fsync(self.fd)
            except FileExistsError:self.fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            self.identity=self._identity()
            try:fcntl.flock(self.fd,mode|fcntl.LOCK_NB)
            except BlockingIOError:raise LifecycleBusy('source lifecycle operation is busy') from None
            if not self.valid():raise ValueError('source lifecycle lock changed')
        except BaseException:self.close();raise

    def _identity(self):
        _same_parents(self.parents);info=os.fstat(self.fd);named=self.path.lstat()
        for item in (info,named):
            if not stat.S_ISREG(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600 or item.st_nlink!=1 or item.st_size:
                raise ValueError('empty owned lifecycle lock required')
        if (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino):raise ValueError('source lifecycle lock replaced')
        return info.st_dev,info.st_ino

    def valid(self):
        try:return self.fd is not None and self._identity()==self.identity
        except (OSError,ValueError):return False

    def close(self):
        if self.fd is not None:
            try:fcntl.flock(self.fd,fcntl.LOCK_UN)
            finally:os.close(self.fd);self.fd=None


class Lifetime:
    def __init__(self,root,data,*,mode='read',control=False):
        self.root,self.data=map(canonical,(root,data));self.mode=mode;self.control=control
        self.key=(str(self.root),str(self.data));self.pid=os.getpid();self.thread=threading.get_ident()
        self.life=self.command=None;self.own_life=self.own_command=False;self.token=None
        if mode not in ('read','write') or type(control) is not bool:raise ValueError('explicit lifetime/control mode required')

    def valid(self):
        return (self.pid==os.getpid() and self.thread==threading.get_ident() and self.life is not None and self.life.valid()
            and (self.command is None or self.command.valid()))

    def __enter__(self):
        if self.token is not None or fcntl is None or not hasattr(os,'O_NOFOLLOW'):raise ValueError('native source lifetime API required')
        previous=_active.get().get(self.key)
        try:
            if previous is not None:
                if not previous.valid():raise ValueError('prior source lifetime ended')
                if self.mode=='write' and previous.mode!='write':raise ValueError('shared source lifetime cannot upgrade in place')
                self.life=previous.life;self.mode=previous.mode;self.command=previous.command
            else:
                authority(self.root,self.data)
                self.life=_Lock(self.data.with_name(self.data.name+'-lifetime.lock'),fcntl.LOCK_EX if self.mode=='write' else fcntl.LOCK_SH);self.own_life=True
                # A remover may have completed after the first authority read.
                authority(self.root,self.data)
            if self.control and self.command is None:
                self.command=_Lock(self.data.with_name(self.data.name+'-control.lock'),fcntl.LOCK_EX);self.own_command=True
            self.token=_active.set(_active.get()|{self.key:self});return self
        except BaseException:self.__exit__();raise

    def __exit__(self,*exc):
        if self.token is not None:_active.reset(self.token);self.token=None
        if self.own_command:self.command.close();self.own_command=False
        if self.own_life:self.life.close();self.own_life=False


class _InheritedLock(_Lock):
    """Close a duplicate without unlocking its parent's open description."""
    def __init__(self,path,fd):
        self.path=path;self.fd=None;self.parents=_parents(path.parent)
        try:
            if type(fd) is not int or fd<3:raise ValueError('explicit inherited source descriptor required')
            self.fd=os.dup(fd);os.set_inheritable(self.fd,False);self.identity=self._identity()
            probe=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:
                try:fcntl.flock(probe,fcntl.LOCK_SH|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:
                    fcntl.flock(probe,fcntl.LOCK_UN)
                    raise ValueError('inherited source lifetime is not exclusive')
            finally:os.close(probe)
            # A foreign exclusive lock on a different open description must
            # not qualify our descriptor. For the inherited one this is a noop.
            try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('inherited source descriptor does not own the exclusive lock') from None
            if not self.valid():raise ValueError('inherited source lock changed')
        except BaseException:self.close();raise

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None


class InheritedLifetime(Lifetime):
    """Explicit installer-child API, never automatic recovery or CLI adoption.

    The parent passes its already-exclusive open descriptor with pass_fds and
    keeps that lock until the child is reaped and GUI completion is inspected.
    Child exit closes only its duplicate and never unlocks the parent's lock.
    """
    def __init__(self,root,data,fd):
        super().__init__(root,data,mode='write');self.inherited_fd=fd

    def __enter__(self):
        if self.token is not None or current(self.root,self.data) is not None:raise ValueError('fresh installer child lifetime required')
        try:
            authority(self.root,self.data)
            self.life=_InheritedLock(self.data.with_name(self.data.name+'-lifetime.lock'),self.inherited_fd);self.own_life=True
            authority(self.root,self.data);self.token=_active.set(_active.get()|{self.key:self});return self
        except BaseException:self.__exit__();raise


def current(root,data):
    value=_active.get().get((str(Path(root)),str(Path(data))))
    return value if value is not None and value.valid() else None


def guarded(*,mode='read',control=False,targets=None):
    def decorate(function):
        signature=inspect.signature(function)
        @functools.wraps(function)
        def invoke(*args,**kwargs):
            bound=signature.bind(*args,**kwargs);bound.apply_defaults()
            root,data=targets() if targets is not None else (bound.arguments['root'],bound.arguments['data'])
            if root is None or data is None:
                import manage
                root=root if root is not None else manage.ROOT;data=data if data is not None else manage.DATA
            with Lifetime(root,data,mode=mode,control=control):return function(*args,**kwargs)
        return invoke
    return decorate


def entry():
    root=Path(__file__).resolve().parents[1];args=sys.argv[1:]
    if not args or args[0] not in ('service','alias','collector','operator'):raise ValueError('explicit native lifecycle entry required')
    kind=args.pop(0)
    mode='read'
    if kind=='collector':
        import argparse
        parser=argparse.ArgumentParser();parser.add_argument('--data-dir',required=True);parser.add_argument('--duration',type=int,default=0)
        parsed=parser.parse_args(args);data=Path(parsed.data_dir);arguments=['--data-dir',str(data),'--duration',str(parsed.duration)]
        module='dnsalias.collector';control=False
    elif kind=='operator':
        if root!=Path('/usr/local/libexec/dnsalias') or not args or args[0] not in ('manage','webupgrade','policydelete','plainsetup','preferenceimport','counterram'):
            raise ValueError('canonical native operator entry required')
        name=args.pop(0);data=Path('/var/db/dnsalias');arguments=args
        module='manage' if name=='manage' else 'dnsalias.'+name
        mode='write' if name=='preferenceimport' or name=='manage' and args and args[0] in ('upgrade','uninstall') else 'read'
        control=name in ('manage','webupgrade','preferenceimport')
        if name=='counterram':control=bool(args and args[0]in('enable','disable','abort'))
    else:
        if root!=Path('/usr/local/libexec/dnsalias'):raise ValueError('native service/alias entry requires the canonical production source; private rc.d scripts are not executable fixtures')
        if len(args)!=1 or args[0] not in (('start','stop','enable','disable','status') if kind=='service' else ('start','stop','run','status','display_status')):raise ValueError('explicit native service operation required')
        data=Path('/var/db/dnsalias');arguments=args;module='dnsalias.serviceboot' if kind=='service' else 'dnsalias.aliasservice';control=args[0] in ('start','stop','enable','disable')
    with Lifetime(root,data,mode=mode,control=control):
        sys.modules['dnsalias.lifecycle']=sys.modules[__name__]
        sys.path.insert(0,str(root));sys.argv=[module,*arguments]
        runpy.run_module(module,run_name='__main__',alter_sys=True)


if __name__=='__main__':entry()
