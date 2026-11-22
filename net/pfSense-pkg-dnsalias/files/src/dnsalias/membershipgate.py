"""Inactive shared membership lease and exclusive permanent disarm primitive.

No PF, process, DNS, rule or configuration actions. Caller owns the private
session directory, namespace, supervision and cleanup. Every writer must use
the same captured gate before its native filter guard. Exclusive disarm fences
future writes, not a writer already operating outside this protocol. Root or
same-owner hostile mutation is out of scope. No automatic retry or re-enrollment.
"""
import hashlib
import os
from pathlib import Path
import stat
import sys
from types import MappingProxyType

from .hookfile import _parents
from .reloadlock import SharedReloadLock,ReloadBusy,UnqualifiedReloadLock,fcntl
from .sourceaudit import SourceAudit,SourceSpec,_path

FORMAT='dnsalias-membership-gate-1'
MARKER=b'1'
MARKER_SHA256=hashlib.sha256(MARKER).hexdigest()


class GateChanged(UnqualifiedReloadLock):pass


def validate(value):
    if (type(value) is not dict or set(value)!={'format','path','uid','gid','device','inode'}
        or value['format']!=FORMAT or not isinstance(value['path'],str)):
        raise ValueError('complete captured membership gate required')
    parts=_path(value['path'])
    if parts[-1]!='membership.gate':raise ValueError('explicit session membership.gate required')
    for key in ('uid','gid','device','inode'):
        # This deployed FreeBSD/Python ABI exposes some ZFS st_dev values as
        # signed64 integers. Keep the opaque native value exactly, including
        # its sign; never normalize it into a different comparison identity.
        lower=-(2**63) if key=='device' else 0
        if type(value[key]) is not int or not lower<=value[key]<(2**32 if key in ('uid','gid') else 2**64):
            raise ValueError('bounded native gate identity required')
    if not value['inode']:raise ValueError('nonzero captured gate inode required')
    return dict(value)


def create(directory,*,uid,gid):
    """Create one private fixed-byte gate, refusing any existing path or retry.

    This changes only a newly created file in the caller's private directory.
    Preserve any partial creation if qualification fails; inspect actual outcome
    before deciding what to do. No default path or delegated file owner.
    """
    if (not sys.platform.startswith('freebsd') or any(type(v) is not int for v in (uid,gid))
        or (uid,gid)!=(os.geteuid(),os.getegid())):
        raise ValueError('native current-owner gate creation required')
    directory=Path(directory);path=directory/'membership.gate';_path(str(path))
    if directory.resolve(strict=True)!=directory:raise ValueError('canonical non-symlink private directory required')
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    fd=None
    try:
        before=os.fstat(parent);named=os.stat(directory,follow_symlinks=False)
        if ((before.st_dev,before.st_ino)!=(named.st_dev,named.st_ino) or before.st_uid!=uid
            or stat.S_IMODE(before.st_mode)!=0o700):raise ValueError('private owned session directory required')
        try:os.stat('membership.disarmed',dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise FileExistsError('disarmed session cannot be re-enrolled')
        fd=os.open(path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        os.fchown(fd,uid,gid);os.fchmod(fd,0o600)
        if os.write(fd,MARKER)!=len(MARKER):raise OSError('short membership marker write')
        os.fsync(fd);os.fsync(parent)
        info=os.fstat(fd)
        descriptor=validate({'format':FORMAT,'path':str(path),'uid':uid,'gid':gid,'device':info.st_dev,'inode':info.st_ino})
        # Qualify the complete canonical ancestor chain and fixed marker inode
        # after creation, before a caller can give this descriptor to a writer.
        gate=MembershipGate(descriptor)
        try:
            with gate:
                if not gate.valid():raise GateChanged('new membership gate qualification failed')
        finally:gate.close()
        return descriptor
    finally:
        if fd is not None:os.close(fd)
        os.close(parent)


class MembershipGate(SharedReloadLock):
    def __init__(self,descriptor,*,disarmed=False):
        if type(disarmed) is not bool or disarmed and type(self) is not ExclusiveMembershipGate:
            raise ValueError('only an exclusive cleanup holder may capture a disarmed gate')
        self.descriptor=MappingProxyType(validate(descriptor));self.source=None;self.source_watch=None;self.disarmed=disarmed;self.disarm_attempted=disarmed
        path=Path(self.descriptor['path'])
        if disarmed:path=path.with_name('membership.disarmed')
        super().__init__(path,expected_uid=self.descriptor['uid'])
        try:
            v=self.descriptor
            self.source=SourceAudit([SourceSpec('membership_gate',str(self.path),v['uid'],v['gid'],(0o600,),1)],
                ancestor_uids=tuple(dict.fromkeys((0,v['uid']))))
            if self.source.hashes!={'membership_gate':MARKER_SHA256} or self.source.files[0][4][:2]!=(v['device'],v['inode']):
                raise GateChanged('membership gate differs from captured marker inode')
            from .sourcewatch import SourceWatch
            self.source_watch=SourceWatch(self.source)
            if disarmed:self._sources()
        except Exception:self.close();raise

    def _busy_reason(self):return 'independent membership cleanup holds the exclusive gate'

    def _validate_identity(self,descriptor,named):
        found=super()._validate_identity(descriptor,named);v=self.descriptor
        for info in (descriptor,named):
            if info.st_gid!=v['gid'] or stat.S_IMODE(info.st_mode)!=0o600 or info.st_size!=len(MARKER):
                raise GateChanged('membership gate permissions or contents changed')
        if found!=(v['device'],v['inode']):raise GateChanged('membership gate inode changed')
        return found

    def _sources(self):
        if self.disarmed:
            # Disarm intentionally changes the named file/ctime. Retain the
            # existing pinned descriptors/ancestor identities without allocating
            # a new audit after the rename. The held fd and new name must still
            # describe the original marker inode under the same private parents.
            _parents(self.source)
            try:os.stat('membership.gate',dir_fd=self.source.files[0][1],follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise GateChanged('an active gate name reappeared; inspect session')
        else:
            self.source_watch.audit()
            try:os.stat('membership.disarmed',dir_fd=self.source.files[0][1],follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise GateChanged('disarmed marker appeared; inspect session ownership')

    def __enter__(self):
        try:
            self._sources();super().__enter__();self._sources();return self
        except Exception as exc:
            super().__exit__()
            if not isinstance(exc,ReloadBusy):self._failed=True
            raise

    def valid(self):
        try:self._sources();return super().valid()
        except (OSError,ValueError,UnqualifiedReloadLock):self._failed=True;return False

    def available(self):
        """Read-only identity check outside an operation; not lock acquisition."""
        if self._closed or self._failed or self.disarmed:return False
        try:self._sources();return True
        except (OSError,ValueError,UnqualifiedReloadLock):self._failed=True;return False

    def close(self):
        try:super().close()
        finally:
            if self.source_watch is not None:self.source_watch.close()
            if self.source is not None:self.source.close()


class ExclusiveMembershipGate(MembershipGate):
    def _mode(self):return fcntl.LOCK_EX
    def _busy_reason(self):return 'a membership operation still holds the shared gate'

    def disarm(self):
        """One atomic namespace disarm while retaining the exclusive inode lock.

        No existing disarmed marker is overwritten. A failure after the rename
        may already have fenced old writers; inspect both names, never repeat
        this mutation. This does not clear any PF table or kill a process.
        """
        if self.disarm_attempted or self.disarmed or not self.valid():raise GateChanged('one held exclusive disarm required')
        self.disarm_attempted=True;parent=self.source.files[0][1];target='membership.disarmed'
        try:
            try:os.stat(target,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise GateChanged('existing disarmed marker requires inspection')
            self._sources();self._identity()
            # The parent is private and pinned. Privileged/same-owner writers
            # bypassing this protocol are excluded, as for the native locks.
            os.rename(self.path.name,target,src_dir_fd=parent,dst_dir_fd=parent)
            self.path=self.path.with_name(target);self.disarmed=True
            os.fsync(parent)
            if not self.valid():raise GateChanged('disarmed gate readback failed')
            return {'disarmed':True,'path':str(self.path),'device':self.descriptor['device'],
                'inode':self.descriptor['inode'],'pf_changed':False,'automatic_retry':False}
        except Exception:
            self._failed=True;raise
