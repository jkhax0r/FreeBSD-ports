"""Read-only phase cache for one already owned hook journal.

Only the validated phase string is retained. Every lookup checks the pinned
file and directory identities, permissions and metadata. A change uses the
unchanged complete journal reader; errors close this reader permanently.
This grants no hook, recovery, writer, TTL or reload authority. Mutations and
all decisions needing the complete journal continue to read it directly.
"""
import os

from .checkpointfile import UntrustedCheckpoint, _ReadReplaced
from .hooktrial import HookTrialFile


def _stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class HookPhaseReader:
    def __init__(self, store):
        if type(store) is not HookTrialFile or store.fd is None:
            raise ValueError('open owned hook journal required')
        self.store = store
        self.fd = None
        self.stamp = self.phase = None
        self.closed = False

    def _forget(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.stamp = self.phase = None

    def _refresh(self):
        self._forget()
        for attempt in range(2):
            fd = None
            try:
                self.store._directory()
                fd = os.open(self.store.NAME, os.O_RDONLY | os.O_NOFOLLOW |
                             os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=self.store.fd)
                before = _stamp(self.store._file(fd, self.store.NAME))
                value = self.store.read()
                after = _stamp(self.store._file(fd, self.store.NAME))
                self.store._directory()
                if before != after:
                    raise _ReadReplaced('hook journal changed during phase read')
                if value is None:
                    raise UntrustedCheckpoint('hook journal missing')
                self.fd, fd = fd, None
                self.stamp = after
                self.phase = value['checkpoint']['status']['phase']
                return self.phase
            except _ReadReplaced as exc:
                if attempt:
                    raise UntrustedCheckpoint('hook journal repeatedly changed') from exc
            finally:
                if fd is not None:
                    os.close(fd)

    def read_phase(self):
        if self.closed:
            raise UntrustedCheckpoint('hook phase reader closed')
        try:
            if self.fd is not None:
                try:
                    self.store._directory()
                    found = _stamp(self.store._file(self.fd, self.store.NAME))
                    self.store._directory()
                    # Also detect an in-place write during the metadata checks.
                    if found == self.stamp == _stamp(os.fstat(self.fd)):
                        return self.phase
                except _ReadReplaced:
                    pass  # A normal atomic save requires a complete new read.
            return self._refresh()
        except Exception:
            self.close()
            raise

    def close(self):
        self._forget()
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
