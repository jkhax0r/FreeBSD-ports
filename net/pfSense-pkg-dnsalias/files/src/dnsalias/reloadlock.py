"""Inactive nonblocking shared guard for a native reload lock file.

No default path, creation, truncation or forced unlock. The caller must qualify
the native lock protocol, hold the guard only for bounded work, and check valid()
before acknowledging an update. A native post-reload hook already holding the
exclusive lock must never synchronously request this guard from the helper.
The first inspected inode stays pinned between acquisitions until close().
Replacement requires a new, independently qualified writer lifetime; retaining
the descriptor also prevents the old inode number being reused unnoticed.
"""
import os
from pathlib import Path
import stat

try:
    import fcntl
except ImportError:
    fcntl=None


class ReloadBusy(RuntimeError): pass
class UnqualifiedReloadLock(RuntimeError): pass


class SharedReloadLock:
    def __init__(self,path,*,expected_uid=0):
        self.path=Path(path)
        if not self.path.is_absolute(): raise ValueError('explicit absolute native lock path required')
        if type(expected_uid) is not int or expected_uid<0: raise ValueError('explicit owner UID required')
        self.uid=expected_uid;self.fd=None;self.identity=None;self.acquisition=0
        self._pin_fd=None;self._pinned_identity=None;self._closed=False;self._failed=False

    def _mode(self):return fcntl.LOCK_SH

    def _busy_reason(self):return 'native filter reload holds exclusive lock'

    def _identity(self):
        return self._validate_identity(os.fstat(self.fd),os.stat(self.path,follow_symlinks=False))

    def _validate_identity(self,descriptor,named):
        # Subclasses validate the same snapshot, without fetching both native
        # metadata records again. Call sites still resample before/after locks.
        for item in (descriptor,named):
            # Native pfSense creates this file mode 0666. Ownership, file kind
            # and inode continuity matter; do not chmod a borrowed native lock.
            if not stat.S_ISREG(item.st_mode) or item.st_uid!=self.uid or item.st_nlink!=1:
                raise UnqualifiedReloadLock('native lock owner/type/link count changed')
        if (descriptor.st_dev,descriptor.st_ino)!=(named.st_dev,named.st_ino):
            raise UnqualifiedReloadLock('native lock path no longer names locked inode')
        return descriptor.st_dev,descriptor.st_ino

    def __enter__(self):
        if self.fd is not None: raise ValueError('guard already held')
        if self._closed or self._failed: raise UnqualifiedReloadLock('native lock lifetime ended')
        if fcntl is None or not hasattr(os,'O_NOFOLLOW'): raise UnqualifiedReloadLock('native lock API unavailable')
        try:
            self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
            self.identity=self._identity()
            if self._pin_fd is None:
                self._pin_fd=os.dup(self.fd);self._pinned_identity=self.identity
            elif self.identity!=self._pinned_identity:
                raise UnqualifiedReloadLock('native reload lock replaced between acquisitions')
            try: fcntl.flock(self.fd,self._mode()|fcntl.LOCK_NB)
            except BlockingIOError as exc: raise ReloadBusy(self._busy_reason()) from exc
            if self._identity()!=self.identity: raise UnqualifiedReloadLock('native lock replaced while acquiring')
            self.acquisition+=1
            return self
        except Exception as exc:
            if not isinstance(exc,ReloadBusy):self._failed=True
            if self.fd is not None:
                os.close(self.fd);self.fd=None
            raise

    def valid(self):
        if self.fd is None or self._closed or self._failed:return False
        try:
            valid=self._identity()==self.identity==self._pinned_identity
        except (OSError,UnqualifiedReloadLock):valid=False
        if not valid:self._failed=True
        return valid

    def __exit__(self,*exc):
        if self.fd is not None:
            try: fcntl.flock(self.fd,fcntl.LOCK_UN)
            finally: os.close(self.fd);self.fd=None

    def close(self):
        self._closed=True
        try:self.__exit__()
        finally:
            if self._pin_fd is not None:
                os.close(self._pin_fd);self._pin_fd=None


class ExclusiveConfigLock(SharedReloadLock):
    """Inactive borrowed native configuration lock for a bounded transaction.

    Inherits noncreation, nontruncation, ownership checks, inode pinning and
    permanent refusal after replacement. A busy reader or writer returns
    immediately. Caller must qualify the actual native path/protocol and hold
    from the fresh read through publication, invalidation and readback. Never
    call native write_config/config_write_file while holding this guard: their
    separate lock acquisition is not reentrant. This is advisory coordination,
    not protection from an editor that captured stale data before lock waiting.
    No default path, work, scheduling or config write is introduced.
    """
    def _mode(self):return fcntl.LOCK_EX

    def _busy_reason(self):return 'native configuration reader or writer holds lock'
