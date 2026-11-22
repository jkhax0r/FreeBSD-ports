"""Inactive owned-file identity capture and cheap native source drift checks.

Only explicit paths, owners, groups, modes and size caps are accepted. Initial
capture hashes at most16MiB across40 files; steady audits read metadata only.
Open descriptors pin original files/directories so named replacements are
detected. Any observed drift suspends this object; it never adopts new bytes.

Run outside DNS callbacks and the receiver loop. File reads and metadata calls
have soft deadlines, not hard filesystem latency guarantees. Metadata equality
does not attest loaded code or prove atomicity against hostile root/same-owner
writers. Controlled load enrollment and runtime/process audits remain required.
No writes, watches, worker creation, credential content or automatic scheduling.
"""
from dataclasses import dataclass
import hashlib
import math
import os
import re
import stat
import sys
import time


class SourceChanged(ValueError): pass


def _path(value):
    if type(value) is not str or len(value)>512 or not re.fullmatch(r'/[A-Za-z0-9_.\-/]+',value):
        raise ValueError('bounded canonical absolute source path required')
    parts=value.split('/')[1:]
    if not 1<=len(parts)<=16 or any(p in ('','.','..') for p in parts):
        raise ValueError('canonical bounded source path required')
    return parts


@dataclass(frozen=True)
class SourceSpec:
    name: str
    path: str
    uid: int
    gid: int
    modes: tuple
    max_bytes: int

    def __post_init__(self):
        if type(self.name) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,47}',self.name):
            raise ValueError('bounded source label required')
        _path(self.path)
        if any(type(n) is not int or not 0<=n<2**32 for n in (self.uid,self.gid)):
            raise ValueError('explicit owner and group required')
        allowed={0o400,0o440,0o444,0o500,0o550,0o555,0o600,0o640,0o644,0o700,0o750,0o755}
        if (type(self.modes) is not tuple or not 1<=len(self.modes)<=4
            or any(type(m) is not int or m not in allowed for m in self.modes)):
            raise ValueError('explicit safe source modes required')
        if type(self.max_bytes) is not int or not 1<=self.max_bytes<=8*1024*1024:
            raise ValueError('bounded source size required')


class SourceAudit:
    # Optional owned extractor assets and vendor-hook sources coexist. Keep
    # every source pinned and audited instead of omitting any to fit the cap.
    MAX_FILES=48
    MAX_DIRECTORIES=128
    MAX_BYTES=16*1024*1024

    def __init__(self,specs,*,ancestor_uids,budget_seconds=1):
        if not sys.platform.startswith('freebsd') or not all(hasattr(os,n) for n in ('O_NOFOLLOW','O_DIRECTORY','O_CLOEXEC')):
            raise ValueError('qualified native source file API required')
        if (type(specs) not in (tuple,list) or not 1<=len(specs)<=self.MAX_FILES
            or any(not isinstance(s,SourceSpec) for s in specs)
            or len({s.name for s in specs})!=len(specs) or len({s.path for s in specs})!=len(specs)):
            raise ValueError('bounded unique source set required')
        if (type(ancestor_uids) is not tuple or not 1<=len(ancestor_uids)<=4
            or any(type(u) is not int or not 0<=u<2**32 for u in ancestor_uids)
            or 0 not in ancestor_uids or any(s.uid not in ancestor_uids for s in specs)):
            raise ValueError('explicit root and source ancestor owners required')
        self.ancestor_uids=ancestor_uids;self.files=[];self.directories={};self.fds=[]
        self.state='capturing';self.reason=None;self.hashes={};self.captured_bytes=0
        self.last_audit=None
        start,deadline=self._deadline(budget_seconds)
        try:
            root=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.fds.append(root)
            self.directories['/']=(None,'/',root,self._directory_metadata(os.fstat(root)))
            for spec in specs:
                self._within(deadline)
                parts=_path(spec.path);parent=root;prefix=''
                for name in parts[:-1]:
                    prefix+='/'+name
                    if prefix not in self.directories:
                        if len(self.directories)>=self.MAX_DIRECTORIES: raise SourceChanged('source directory cap exceeded')
                        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                        self.fds.append(fd)
                        self.directories[prefix]=(parent,name,fd,self._directory_metadata(os.fstat(fd)))
                    parent=self.directories[prefix][2]
                name=parts[-1]
                # Reject special files before open, then verify the actual fd.
                self._file_metadata(os.stat(name,dir_fd=parent,follow_symlinks=False),spec)
                fd=os.open(name,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                self.fds.append(fd);before=self._file_metadata(os.fstat(fd),spec)
                if self.captured_bytes+before[6]>self.MAX_BYTES: raise SourceChanged('aggregate source byte cap exceeded')
                digest=hashlib.sha256();read=0
                while read<=spec.max_bytes:
                    self._within(deadline)
                    block=os.read(fd,min(65536,spec.max_bytes+1-read))
                    if not block:break
                    read+=len(block);digest.update(block)
                if read!=before[6]: raise SourceChanged('source changed size during capture')
                self.files.append((spec,parent,name,fd,before))
                self.captured_bytes+=read;self.hashes[spec.name]=digest.hexdigest()
            self._verify(deadline)
            self.state='qualified';self.last_audit=time.monotonic()
            self.capture_ms=(self.last_audit-start)*1000
        except (OSError,ValueError) as exc:
            self._fail(exc);raise SourceChanged(self.reason) from exc

    def _deadline(self,budget):
        if type(budget) not in (int,float) or not math.isfinite(budget) or not 0<budget<=1:
            raise ValueError('bounded source audit budget required')
        start=time.monotonic()
        if self.last_audit is not None and start<self.last_audit: raise SourceChanged('source audit clock regressed')
        return start,start+budget

    @staticmethod
    def _within(deadline):
        if time.monotonic()>=deadline: raise SourceChanged('source audit deadline exceeded')

    def _directory_metadata(self,i):
        mode=stat.S_IMODE(i.st_mode)
        sticky_root=i.st_uid==0 and bool(mode&stat.S_ISVTX)
        if (not stat.S_ISDIR(i.st_mode) or i.st_uid not in self.ancestor_uids or mode&0o6000
            or (mode&0o022 and not sticky_root)):
            raise SourceChanged('source ancestor owner or mode refused')
        return i.st_dev,i.st_ino,i.st_uid,i.st_gid,mode

    @staticmethod
    def _file_metadata(i,spec):
        if (not stat.S_ISREG(i.st_mode) or (i.st_uid,i.st_gid)!=(spec.uid,spec.gid)
            or stat.S_IMODE(i.st_mode) not in spec.modes or i.st_nlink!=1 or not 0<i.st_size<=spec.max_bytes):
            raise SourceChanged('source owner, mode, links, type or size refused')
        return i.st_dev,i.st_ino,i.st_uid,i.st_gid,stat.S_IMODE(i.st_mode),i.st_nlink,i.st_size,i.st_mtime_ns,i.st_ctime_ns

    def _verify(self,deadline):
        for path,(parent,name,fd,wanted) in self.directories.items():
            self._within(deadline)
            named=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat('/',follow_symlinks=False)
            if self._directory_metadata(os.fstat(fd))!=wanted or self._directory_metadata(named)!=wanted:
                raise SourceChanged('source ancestor changed: '+path)
        for spec,parent,name,fd,wanted in self.files:
            self._within(deadline)
            try:
                pinned=self._file_metadata(os.fstat(fd),spec)
                named=self._file_metadata(os.stat(name,dir_fd=parent,follow_symlinks=False),spec)
            except (OSError,SourceChanged) as exc:
                raise SourceChanged('source unavailable or ownership changed: '+spec.name) from exc
            if pinned!=wanted or named!=wanted:
                raise SourceChanged('source metadata changed: '+spec.name)
        self._within(deadline)

    def _fail(self,exc):
        self.state='suspended';self.reason=str(exc) if isinstance(exc,SourceChanged) else 'source capture failed: '+type(exc).__name__
        self._close_fds()

    def audit(self,*,budget_seconds=1):
        """Metadata only; mismatch is sticky and returns no trusted hashes."""
        if self.state!='qualified': raise SourceChanged(self.reason or 'source audit closed')
        try:
            start,deadline=self._deadline(budget_seconds)
            self._verify(deadline);finished=time.monotonic()
            self.last_audit=finished
            return {'sources':dict(self.hashes),'checked_monotonic':finished,'duration_ms':(finished-start)*1000,
                    'content_bytes_read':0,'loaded_source_verified':False,'enforcement_qualified':False}
        except (OSError,ValueError) as exc:
            self._fail(exc);raise SourceChanged(self.reason) from exc

    def _close_fds(self):
        while self.fds:
            fd=self.fds.pop()
            try:os.close(fd)
            except OSError:pass

    def close(self):
        self._close_fds()
        if self.state!='suspended':self.state='closed'

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
