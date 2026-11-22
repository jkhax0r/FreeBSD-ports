"""Inactive one-use native config-cache capture and installation completion.

No default path, scheduling, cache parsing or configuration/PF/rule mutation.
Capture pins canonical non-symlink parents and, when present, one private native
cache inode. Invalidation never adopts a replacement. A missing cache is an
explicit valid capture, useful after an inspected interrupted invalidation.
Normal native readers can recreate cache after our observation; this is not a
permanent-absence guarantee. Same-owner/root hostile races remain out of scope.
"""
import copy
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import stat
import time

from .aliasinstall import AliasInstallFile
from .aliasremove import AliasRemovalFile,bound_installation
from .aliasrefs import _tree_digest
from .checkpoint import identity
from .configcodec import NativeConfigCodec
from .hookfile import _read
from .reloadlock import ExclusiveConfigLock,SharedReloadLock
from .sourceaudit import SourceAudit,_path


class ConfigCacheChanged(ValueError):pass


class NativeConfigCache:
    def __init__(self,path,*,expected_uid,expected_gid):
        self.path=Path(path);parts=_path(str(self.path))
        if parts[-1]!='config.cache' or any(type(v) is not int or not 0<=v<2**32 for v in (expected_uid,expected_gid)):
            raise ValueError('explicit native cache path and owner/group required')
        self.uid=expected_uid;self.gid=expected_gid;self.parents=[];self.file=None;self.metadata=None
        self.state='capturing';self.deletion_attempted=False;self.was_present=False
        try:
            fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.parents.append((None,'/',fd,None))
            self.parents[-1]=(None,'/',fd,self._directory(os.fstat(fd)))
            for name in parts[:-1]:
                parent=fd;fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
                self.parents.append((parent,name,fd,None))
                self.parents[-1]=(parent,name,fd,self._directory(os.fstat(fd)))
            self.parent=fd;self.name=parts[-1]
            try:named=os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
            except FileNotFoundError:named=None
            if named is not None:
                self._file(named)
                self.file=os.open(self.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.parent)
                self.metadata=self._file(os.fstat(self.file));self.was_present=True
            self.state='captured';self._verify()
        except Exception:
            self.close();raise

    def _directory(self,info):
        mode=stat.S_IMODE(info.st_mode);sticky=info.st_uid==0 and bool(mode&stat.S_ISVTX)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,self.uid) or mode&0o6000 or (mode&0o022 and not sticky):
            raise ConfigCacheChanged('native cache parent ownership refused')
        return info.st_dev,info.st_ino,info.st_uid,info.st_gid,mode

    def _file(self,info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=self.uid or info.st_gid!=self.gid
            or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1 or not 0<=info.st_size<=16*1024*1024):
            raise ConfigCacheChanged('native cache ownership or type refused')
        return info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns

    def _parents(self):
        for parent,name,fd,wanted in self.parents:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat('/',follow_symlinks=False)
            if self._directory(os.fstat(fd))!=wanted or self._directory(named)!=wanted:
                raise ConfigCacheChanged('native cache parent replaced')

    def _absent(self):
        self._parents()
        try:os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
        except FileNotFoundError:return
        raise ConfigCacheChanged('native cache appeared or was recreated; inspect new outcome')

    def _verify(self):
        if self.state!='captured':raise ConfigCacheChanged('native cache capture lifetime ended')
        self._parents()
        if self.metadata is None:self._absent()
        elif (self._file(os.fstat(self.file))!=self.metadata or
              self._file(os.stat(self.name,dir_fd=self.parent,follow_symlinks=False))!=self.metadata):
            raise ConfigCacheChanged('captured native cache changed')

    def invalidate(self):
        try:
            self._verify()
            if self.metadata is not None:
                self.deletion_attempted=True;os.unlink(self.name,dir_fd=self.parent)
            os.fsync(self.parent);self._absent();self.state='invalidated'
            return {'was_present':self.was_present,'deletion_attempted':self.deletion_attempted,'absent_observed':True}
        except Exception:
            self.state='failed';raise

    def close(self):
        if self.file is not None:os.close(self.file);self.file=None
        while self.parents:os.close(self.parents.pop()[2])
        self.state='closed'


class ConfigCompletionError(ValueError):
    def __init__(self,*,stage,cache_deletion_attempted):
        super().__init__('configuration completion incomplete during '+stage+'; inspect file, cache and receipt')
        self.stage=stage;self.cache_deletion_attempted=cache_deletion_attempted


def complete_install(audit,config_guard,reload_guard,codec,journal,cache,*,boot_id):
    """Finish an already-recorded publication; never repeat its file write.

    Consumes the fresh config audit and cache capture on every outcome. Caller
    retains the held guards, codec and receipt. The cache must share the native
    config/filter lock directory. Exact target file/tree readback is required
    before invalidation and before the completion record. Changed/uncertain
    receipts and unrelated later config edits require separate inspection.
    """
    return _complete(audit,config_guard,reload_guard,codec,journal,cache,boot_id=boot_id,installation=None)


def complete_unused_removal(audit,config_guard,reload_guard,codec,journal,installation,cache,*,boot_id):
    """Complete cache handling for an already-published unused-alias removal."""
    if type(installation) is not AliasInstallFile:
        if isinstance(audit,SourceAudit):audit.close()
        if isinstance(cache,NativeConfigCache):cache.close()
        raise ValueError('owned installation journal required')
    return _complete(audit,config_guard,reload_guard,codec,journal,cache,boot_id=boot_id,installation=installation)


def _complete(audit,config_guard,reload_guard,codec,journal,cache,*,boot_id,installation):
    if not isinstance(audit,SourceAudit) or not isinstance(cache,NativeConfigCache):
        raise ValueError('fresh native config audit and explicit cache capture required')
    deadline=time.monotonic()+2;stage='validation'
    def guarded():
        if time.monotonic()>=deadline:raise ValueError('configuration completion deadline')
        if (type(config_guard) is not ExclusiveConfigLock or type(reload_guard) is not SharedReloadLock
            or not config_guard.valid() or not reload_guard.valid() or config_guard.identity==reload_guard.identity
            or config_guard.path.name!='config.lock' or reload_guard.path.name!='filter.lock'
            or config_guard.path.parent!=cache.path.parent or reload_guard.path.parent!=cache.path.parent):
            raise ValueError('held native config/filter guards must bind the cache directory')
    try:
        identity(boot_id);guarded()
        journal_type=AliasInstallFile if installation is None else AliasRemovalFile
        if not isinstance(codec,NativeConfigCodec) or type(journal) is not journal_type:raise ValueError('qualified codec and owned receipt required')
        if audit.state!='qualified' or len(audit.files)!=1:raise ValueError('fresh single config capture required')
        entry=audit.files[0];spec=entry[0];receipt=journal.read()
        if receipt is None:raise ValueError('recorded publication required')
        value=receipt['checkpoint'];plan=value['plan'];status=value['status']
        def check_installation():
            if installation is not None:
                if installation.uid!=journal.uid:raise ValueError('installation/removal ownership differs')
                bound_installation(value,installation.read())
        check_installation()
        if (status['phase']!='published' or plan['boot_id']!=boot_id or not status['directory_synced']
            or status['cache_invalidated'] or plan['config']!=(asdict(spec)|{'modes':list(spec.modes)})
            or spec.name!='firewall_config' or journal.uid!=spec.uid or (cache.uid,cache.gid)!=(spec.uid,spec.gid)):
            raise ValueError('only the exact owned pending publication can complete')
        stage='configuration_readback';raw=_read(audit,entry,deadline)
        if hashlib.sha256(raw).hexdigest()!=plan['after_file_sha256']:raise ValueError('published config changed')
        decoded=codec.decode(raw)['configuration']
        if _tree_digest(decoded)!=plan['after_tree_sha256']:raise ValueError('published config tree changed')
        guarded();audit.audit()
        if journal.read()!=receipt:raise ValueError('publication receipt changed')
        check_installation()
        stage='cache_invalidation';result=cache.invalidate();guarded();audit.audit()
        if hashlib.sha256(_read(audit,entry,deadline)).hexdigest()!=plan['after_file_sha256']:
            raise ValueError('config changed during cache invalidation')
        cache._absent();guarded();check_installation()
        updated=copy.deepcopy(value);updated['status'].update(phase='complete',updated_monotonic=time.monotonic(),
            updated_utc=time.time(),cache_invalidated=True)
        stage='receipt_record';digest=journal.save(updated,expected_digest=receipt['file_sha256'])
        guarded();audit.audit()
        return {'publication_complete':True,'configuration_changed':False,'filter_reloaded':False,
            'cache':result,'receipt_sha256':digest,'configuration_sha256':plan['after_file_sha256']}
    except Exception:
        raise ConfigCompletionError(stage=stage,cache_deletion_attempted=cache.deletion_attempted) from None
    finally:
        try:cache.close()
        finally:audit.close()
