"""Inactive owned-file checkpoint persistence, with no default live path.

The directory must already be privately owned by the expected UID. Files are
authenticated by OS ownership/type/permissions, not a cryptographic signature;
the embedded hash detects corruption. Recovery still requires checkpoint.restore
with a separately qualified boot/profile identity and clock pair. No installer
or collector currently provisions or uses this store.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat

from .ipc import strict_pairs,finite_float,invalid_number
from .reloadlock import fcntl


class UntrustedCheckpoint(ValueError): pass
class CheckpointBusy(RuntimeError): pass
class _ReadReplaced(UntrustedCheckpoint): pass

NAME='lease-checkpoint.json'
PENDING='lease-checkpoint.pending'
LOCK='lease-checkpoint.lock'
MAX_BYTES=4*1024*1024


def encode(value):
    try: raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    except (ValueError,TypeError,RecursionError) as exc: raise UntrustedCheckpoint('checkpoint encoding refused') from exc
    if len(raw)>MAX_BYTES: raise UntrustedCheckpoint('checkpoint size limit')
    return raw


def checksum(raw): return hashlib.sha256(raw).hexdigest()


class CheckpointFile:
    # Fixed formats/names may be specialized by another reviewed owned store.
    # They are not caller-controlled paths or runtime configuration options.
    NAME=NAME
    PENDING=PENDING
    LOCK=LOCK
    ENVELOPE_FORMAT='dnsalias-owned-checkpoint-1'
    PAYLOAD_FORMAT='dnsalias-checkpoint-1'

    def __init__(self,directory,*,expected_uid=0):
        self.path=Path(directory);self.fd=None
        if not self.path.is_absolute() or type(expected_uid) is not int or expected_uid<0:
            raise ValueError('absolute owned directory and UID required')
        if fcntl is None or not hasattr(os,'O_NOFOLLOW'): raise UntrustedCheckpoint('qualified POSIX file API required')
        self.uid=expected_uid
        self.fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try: self.directory_identity=self._directory()
        except Exception: self.close();raise

    def _directory(self):
        if self.fd is None: raise UntrustedCheckpoint('checkpoint store closed')
        own=os.fstat(self.fd);named=os.stat(self.path,follow_symlinks=False)
        for item in (own,named):
            if not stat.S_ISDIR(item.st_mode) or item.st_uid!=self.uid or stat.S_IMODE(item.st_mode)!=0o700:
                raise UntrustedCheckpoint('private owned directory required')
        if (own.st_dev,own.st_ino)!=(named.st_dev,named.st_ino):
            raise UntrustedCheckpoint('checkpoint directory replaced')
        found=own.st_dev,own.st_ino
        if hasattr(self,'directory_identity') and found!=self.directory_identity:
            raise UntrustedCheckpoint('checkpoint directory identity changed')
        return found

    def _file(self,fd,name):
        own=os.fstat(fd);named=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        if (name==self.NAME and own.st_nlink in (0,1) and named.st_nlink==1
            and (own.st_dev,own.st_ino)!=(named.st_dev,named.st_ino)
            and all(stat.S_ISREG(item.st_mode) and item.st_uid==self.uid
                    and stat.S_IMODE(item.st_mode)==0o600 for item in (own,named))):
            # A cooperating atomic save can unlink the reader's already-open
            # old inode, including BETWEEN fstat and stat above. Confirm its
            # current unlink state before permitting the one read-only reopen.
            # A renamed-but-still-linked file is not the atomic-save contract.
            current=os.fstat(fd)
            if (current.st_nlink==0 and (current.st_dev,current.st_ino)==(own.st_dev,own.st_ino)
                and stat.S_ISREG(current.st_mode) and current.st_uid==self.uid
                and stat.S_IMODE(current.st_mode)==0o600):
                raise _ReadReplaced('checkpoint atomically replaced during read')
        for item in (own,named):
            if not stat.S_ISREG(item.st_mode) or item.st_uid!=self.uid or stat.S_IMODE(item.st_mode)!=0o600 or item.st_nlink!=1:
                raise UntrustedCheckpoint('checkpoint file owner/type/mode/links unqualified')
        if (own.st_dev,own.st_ino)!=(named.st_dev,named.st_ino):
            raise UntrustedCheckpoint('checkpoint file replaced')
        return own

    @contextmanager
    def _locked(self):
        self._directory()
        fd=os.open(self.LOCK,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,0o600,dir_fd=self.fd)
        try:
            if self._file(fd,self.LOCK).st_size: raise UntrustedCheckpoint('unexpected checkpoint lock content')
            try: fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError as exc: raise CheckpointBusy('another checkpoint writer is active') from exc
            self._file(fd,self.LOCK);self._directory()
            yield
        finally: os.close(fd)

    def read(self):
        for attempt in range(2):
            try:return self._read_once()
            except _ReadReplaced as exc:
                if attempt:raise UntrustedCheckpoint('checkpoint repeatedly replaced during read') from exc

    def _read_once(self):
        self._directory()
        try: fd=os.open(self.NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=self.fd)
        except FileNotFoundError: return None
        try:
            before=self._file(fd,self.NAME)
            if not 0<before.st_size<=MAX_BYTES: raise UntrustedCheckpoint('invalid checkpoint size')
            chunks=[];remaining=MAX_BYTES+1
            while remaining:
                block=os.read(fd,min(65536,remaining))
                if not block: break
                chunks.append(block);remaining-=len(block)
            raw=b''.join(chunks);after=self._file(fd,self.NAME)
            if (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)!=before.st_size:
                raise UntrustedCheckpoint('checkpoint changed while reading')
            self._directory()
        finally: os.close(fd)
        try:
            value=json.loads(raw.decode(),object_pairs_hook=strict_pairs,parse_float=finite_float,parse_constant=invalid_number)
            if type(value) is not dict or set(value)!={'format','checkpoint','sha256'} or value['format']!=self.ENVELOPE_FORMAT:
                raise ValueError('envelope')
            if type(value['checkpoint']) is not dict or value['checkpoint'].get('format')!=self.PAYLOAD_FORMAT: raise ValueError('payload')
            if value['sha256']!=checksum(encode(value['checkpoint'])): raise ValueError('digest')
        except (UnicodeError,ValueError,TypeError,RecursionError) as exc:
            raise UntrustedCheckpoint('checkpoint envelope or integrity check failed') from exc
        return {'checkpoint':value['checkpoint'],'file_sha256':checksum(raw)}

    def save(self,checkpoint,*,expected_digest):
        if type(checkpoint) is not dict or checkpoint.get('format')!=self.PAYLOAD_FORMAT:
            raise UntrustedCheckpoint('checkpoint snapshot required')
        body=encode(checkpoint)
        raw=encode({'format':self.ENVELOPE_FORMAT,'checkpoint':checkpoint,'sha256':checksum(body)})
        with self._locked():
            previous=self.read()
            if (previous['file_sha256'] if previous else None)!=expected_digest:
                raise UntrustedCheckpoint('checkpoint changed; inspect current outcome before retry')
            # Never adopt/remove a pending file left by another or crashed save.
            fd=os.open(self.PENDING,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            pending_identity=None
            try:
                own=self._file(fd,self.PENDING);pending_identity=own.st_dev,own.st_ino
                view=memoryview(raw)
                while view:
                    written=os.write(fd,view)
                    if written<=0: raise OSError('short checkpoint write')
                    view=view[written:]
                os.fsync(fd)
                self._file(fd,self.PENDING);self._directory()
                current=self.read()
                if (current['file_sha256'] if current else None)!=expected_digest:
                    raise UntrustedCheckpoint('checkpoint changed before commit')
                os.replace(self.PENDING,self.NAME,src_dir_fd=self.fd,dst_dir_fd=self.fd)
                # If this fails, the rename may already be visible: read it
                # before deciding whether to retry. Never erase the new target.
                os.fsync(self.fd)
                self._directory()
                return checksum(raw)
            finally:
                os.close(fd)
                try: leftover=os.stat(self.PENDING,dir_fd=self.fd,follow_symlinks=False)
                except FileNotFoundError: leftover=None
                if leftover is not None and pending_identity==(leftover.st_dev,leftover.st_ino):
                    os.unlink(self.PENDING,dir_fd=self.fd)

    def close(self):
        if self.fd is not None: os.close(self.fd);self.fd=None

    def __enter__(self): return self
    def __exit__(self,*exc): self.close()
