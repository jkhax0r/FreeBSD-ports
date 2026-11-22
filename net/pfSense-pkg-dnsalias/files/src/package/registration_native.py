"""Explicit owned GUI metadata publication using the installed native adapters.

No default paths, file provisioning, source install/removal, service actions,
resolver changes or PF mutations. The installer must separately serialize its
source/UI/rc.d lifecycle and supply freshly qualified native locks, config,
codec, cache and a private receipt store. This layer publishes only the owned
menu/service/Enable plan. Interrupted outcomes are inspected, never replayed.
"""
from dataclasses import asdict
import hashlib
import os
from pathlib import Path
import time

from dnsalias.checkpointfile import CheckpointFile
from dnsalias.configcache import NativeConfigCache
from dnsalias.configcodec import NativeConfigCodec
from dnsalias.hookfile import _pending,_parents,_read
from dnsalias.reloadlock import ExclusiveConfigLock,SharedReloadLock
from dnsalias.sourceaudit import SourceAudit
from . import registration as plan

PENDING='config.xml.dnsalias-gui.pending'


class RegistrationFile(CheckpointFile):
    NAME='gui-registration.json';PENDING='gui-registration.pending';LOCK='gui-registration.lock'
    ENVELOPE_FORMAT='dnsalias-gui-registration-envelope-1';PAYLOAD_FORMAT='dnsalias-gui-registration-1'


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _guards(config_guard,reload_guard):
    if (type(config_guard) is not ExclusiveConfigLock or type(reload_guard) is not SharedReloadLock
        or not config_guard.valid() or not reload_guard.valid() or config_guard.identity==reload_guard.identity
        or config_guard.path.name!='config.lock' or reload_guard.path.name!='filter.lock'
        or config_guard.path.parent!=reload_guard.path.parent):
        raise ValueError('distinct held native configuration/filter guards required')


def _config(config,journal):
    if type(journal) is not RegistrationFile or type(config) is not SourceAudit or config.state!='qualified' or len(config.files)!=1:
        raise ValueError('one qualified native config and owned GUI receipt store required')
    entry=config.files[0];spec=entry[0]
    if spec.name!='firewall_config' or Path(spec.path).name!='config.xml' or spec.modes!=(0o600,) or spec.uid!=journal.uid:
        raise ValueError('private native config.xml identity required')
    config.audit();return entry


def _spec(spec):return asdict(spec)|{'modes':list(spec.modes)}


def _previous(journal,spec,*,allow_pending=False):
    if not allow_pending and (journal.path/journal.PENDING).exists():raise ValueError('pending GUI receipt requires inspection')
    previous=journal.read()
    if previous is None:return None
    value=previous['checkpoint']
    if (set(value)!={'format','operation','phase','configuration','before_sha256','after_sha256','directory_synced','cache_invalidated'}
        or value['format']!=journal.PAYLOAD_FORMAT or value['operation'] not in ('install','migrate','remove')
        or value['phase'] not in ('prepared','replaced','installed','removed') or value['configuration']!=_spec(spec)
        or any(type(value[k]) is not str or len(value[k])!=64 or any(c not in '0123456789abcdef' for c in value[k]) for k in ('before_sha256','after_sha256'))
        or value['before_sha256']==value['after_sha256']
        or any(type(value[k]) is not bool for k in ('directory_synced','cache_invalidated'))
        or value['phase']=='prepared' and (value['directory_synced'] or value['cache_invalidated'])
        or value['phase']=='replaced' and (not value['directory_synced'] or value['cache_invalidated'])
        or value['phase'] in ('installed','removed') and (not value['directory_synced'] or not value['cache_invalidated'])
        or value['phase']=='installed' and value['operation'] not in ('install','migrate')
        or value['phase']=='removed' and value['operation']!='remove'):
        raise ValueError('GUI publication receipt changed')
    return previous


def _absent(parent,name):
    try:os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:return
    raise ValueError('pending GUI configuration requires inspection')


def _write(fd,raw):
    view=memoryview(raw)
    while view:
        count=os.write(fd,view)
        if count<=0:raise OSError('short native configuration write')
        view=view[count:]
    os.fsync(fd)


def apply(action,*,journal,config,codec,cache,config_guard,reload_guard,legacy_configuration_sha256=None):
    """Publish only a reviewed native GUI plan under caller-held native guards."""
    if action not in ('install','migrate','remove'):raise ValueError('explicit GUI install/migrate/remove required')
    _guards(config_guard,reload_guard);entry=_config(config,journal);spec,parent,name,_,_=entry
    if (type(codec) is not NativeConfigCodec or type(cache) is not NativeConfigCache or cache.state!='captured'
        or cache.path!=config_guard.path.parent/'config.cache' or cache.uid!=spec.uid or cache.gid!=spec.gid):
        raise ValueError('qualified matching native converter and cache required')
    cache._verify();_absent(parent,PENDING)
    previous=_previous(journal,spec)
    if previous is not None and previous['checkpoint']['phase'] not in ('installed','removed'):
        raise ValueError('incomplete GUI publication requires inspection; no replay')
    before=_read(config,entry,time.monotonic()+1);current=codec.decode(before)['configuration']
    if action=='migrate' and (previous is not None or legacy_configuration_sha256!=_sha(before)):
        raise ValueError('unchanged explicitly reviewed legacy configuration required; no migration replay')
    if action!='migrate' and legacy_configuration_sha256 is not None:raise ValueError('legacy proof is only valid for explicit migration')
    if action=='remove' and (previous is None or previous['checkpoint']['phase']!='installed'):
        raise ValueError('completed owned GUI installation required before removal')
    result=getattr(plan,action)(current);candidate=result['configuration']
    if action=='install' and not result['changed']:
        if previous is None or previous['checkpoint']['phase']!='installed':raise ValueError('owned GUI receipt required; no metadata adoption')
        return {'changed':False,'registered':True,'configuration_changed':False,'services_started':False,'rules_created':False}
    if action=='install' and previous is not None and previous['checkpoint']['phase']=='installed':
        raise ValueError('owned GUI metadata disappeared; inspect before reinstalling')
    converted=codec.encode(candidate)['xml'];raw=converted.encode() if isinstance(converted,str) else converted
    value={'format':journal.PAYLOAD_FORMAT,'operation':action,'phase':'prepared','configuration':_spec(spec),
        'before_sha256':_sha(before),'after_sha256':_sha(raw),'directory_synced':False,'cache_invalidated':False}
    digest=journal.save(value,expected_digest=previous['file_sha256'] if previous else None)
    fd=os.open(PENDING,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        os.fchown(fd,spec.uid,spec.gid);os.fchmod(fd,0o600);_write(fd,raw)
        identity=_pending(fd,parent,PENDING,spec,0o600)
        _guards(config_guard,reload_guard);config.audit();_parents(config);cache._verify()
        _pending(fd,parent,PENDING,spec,0o600,identity)
        os.replace(PENDING,name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
    finally:os.close(fd)
    value.update(phase='replaced',directory_synced=True);digest=journal.save(value,expected_digest=digest)
    cache.invalidate()
    with SourceAudit([spec],ancestor_uids=config.ancestor_uids) as fresh:
        observed=_read(fresh,fresh.files[0],time.monotonic()+1)
        if _sha(observed)!=value['after_sha256'] or codec.decode(observed)['configuration']!=candidate:
            raise ValueError('GUI publication readback differs; inspect before any further action')
    _guards(config_guard,reload_guard)
    value.update(phase='installed' if action in ('install','migrate') else 'removed',cache_invalidated=True)
    journal.save(value,expected_digest=digest)
    return {'changed':True,'registered':action in ('install','migrate'),'configuration_changed':True,
        'services_started':False,'rules_created':False,'before_sha256':value['before_sha256'],'after_sha256':value['after_sha256']}


def inspect(*,journal,config,codec):
    """Bounded file/config evidence without finishing, replaying or recovery."""
    entry=_config(config,journal);spec,parent,_,_,_=entry
    if type(codec) is not NativeConfigCodec:raise ValueError('qualified native converter required')
    raw=_read(config,entry,time.monotonic()+1);current=codec.decode(raw)['configuration'];previous=_previous(journal,spec,allow_pending=True)
    value=previous['checkpoint'] if previous else None
    current_hash=_sha(raw)
    observed='no_receipt' if value is None else ('before' if current_hash==value['before_sha256'] else 'after' if current_hash==value['after_sha256'] else 'changed')
    try:view=plan.inspect(current)
    except ValueError as exc:view={'error':str(exc)[:200]}
    try:pending=os.stat(PENDING,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:pending=None
    return {'receipt':value,'current_config_sha256':current_hash,'observed_config':observed,'registration':view,
        'pending_configuration_present':pending is not None,'pending_receipt_present':(journal.path/journal.PENDING).exists(),
        'automatic_recovery':False,'configuration_changed':False,'services_started':False,'rules_created':False}
