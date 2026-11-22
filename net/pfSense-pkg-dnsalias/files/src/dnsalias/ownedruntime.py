"""Exact cleanup of a private owner runtime after its resources are released."""
import hashlib
import os
from pathlib import Path
import stat

from .blocktrial import gate_identity


def runtime_path(directory):
    """Never adopt a child; allow a root-owned sticky native /var/run parent."""
    path=Path(directory);parent=path.parent.lstat();mode=stat.S_IMODE(parent.st_mode)
    if (not path.is_absolute() or '..' in path.parts or len(os.fsencode(path/'control.sock'))>103
        or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0
        or mode&0o022 and not mode&stat.S_ISVTX):
        raise ValueError('root-controlled or root-owned sticky runtime parent required')
    return path


def remove_runtime(receipt,digest,gate,inode,table=None):
    """Preserve any changed receipt, file, inode or unexpected directory entry."""
    path=Path(gate).parent
    receipt._directory()
    current=receipt.read()
    if current is None or current['file_sha256']!=digest:raise ValueError('runtime receipt changed')
    expected={'gate',receipt.NAME,receipt.LOCK}
    if table is not None:expected|={'table-owner.json','table-owner.lock'}
    descriptor=None if table is None else getattr(table,'membership_gate_descriptor',None)
    if descriptor is not None:
        from .membershipgate import ExclusiveMembershipGate
        from .registeredcleanup import DrainFile
        if table.state!='released' or table.failed:raise ValueError('released registered session required')
        fence=ExclusiveMembershipGate(descriptor,disarmed=True)
        try:
            with fence,DrainFile(path,expected_uid=0) as store:
                record=store.read()
                if record is None:raise ValueError('completed registered drain required')
                value=record['checkpoint']
                if (value['phase']!='complete' or not value['empty_verified'] or value['gate']!=descriptor
                    or value['table']!=table.spec['table'] or value['installation_sha256']!=table.authority.digest
                    or value['boot_id']!=table.authority.boot or not fence.valid()):
                    raise ValueError('registered runtime drain proof changed')
                expected|={'membership.disarmed',store.NAME,store.LOCK}
        finally:fence.close()
    if set(p.name for p in path.iterdir())!=expected or gate_identity(gate)!=inode:
        raise ValueError('runtime contents changed')
    identities={}
    for name in expected:
        item=(path/name).lstat()
        if (not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_nlink!=1
            or stat.S_IMODE(item.st_mode)!=0o600 or item.st_size>65536):
            raise ValueError('runtime file ownership changed')
        identities[name]=(item.st_dev,item.st_ino)
    if table is not None and hashlib.sha256((path/'table-owner.json').read_bytes()).hexdigest()!=table.digest:
        raise ValueError('completed table receipt changed')
    for name in sorted(identities,key=lambda name:(name==receipt.NAME,name)):
        item=(path/name).lstat()
        if (item.st_dev,item.st_ino)!=identities[name]:raise ValueError('runtime file replaced')
        (path/name).unlink()
    receipt.close();path.rmdir()
