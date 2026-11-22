"""Fresh native GUI/service setup coordinator; no production defaults or CLI.

Called only by a serialized installer with verified managed source, a private
installer receipt store and held native config/filter locks. Publish disabled
settings first, then the owned rc.d file, then the authenticated page. This
never starts a service, prepares DNS, creates an alias/rule or installs source.
Removal requires stopped owners and no remaining DNS alias/hook ownership.
Legacy migration and updates remain separate entry points.
Partial outcomes require inspection; neither install nor inspect resumes them.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import time

import manage
from dnsalias.checkpointfile import CheckpointFile
from dnsalias.configcodec import NativeConfigCodec
from dnsalias.hookfile import _read
from dnsalias.sourceaudit import SourceAudit,SourceSpec
from dnsalias import serviceboot
from dnsalias.lifecycle import guarded
from . import bootstrap
from . import registration as plan
from . import registration_native as native


class SetupFile(CheckpointFile):
    NAME='gui-setup.json';PENDING='gui-setup.pending';LOCK='gui-setup.lock'
    ENVELOPE_FORMAT='dnsalias-gui-setup-envelope-1';PAYLOAD_FORMAT='dnsalias-gui-setup-1'


class UpdateFile(CheckpointFile):
    NAME='gui-update.json';PENDING='gui-update.pending';LOCK='gui-update.lock'
    ENVELOPE_FORMAT='dnsalias-gui-update-envelope-1';PAYLOAD_FORMAT='dnsalias-gui-update-1'


def update_record(update):
    path=update.path/update.NAME
    if not path.exists() and not path.is_symlink():return None
    previous=update.read()
    if previous is None:return None
    value=previous['checkpoint']
    base={'format','phase','before','candidate_sha256','setup_before_sha256','configuration_before_sha256'}
    if (value.get('format')!=UpdateFile.PAYLOAD_FORMAT or value.get('phase') not in ('prepared','source_replaced','complete')
        or set(value)!=(base if value.get('phase')=='prepared' else base|{'after','previous_source'})
        or any(type(value.get(k)) is not str or len(value[k])!=64 or any(c not in '0123456789abcdef' for c in value[k])
            for k in ('candidate_sha256','setup_before_sha256','configuration_before_sha256'))
        or type(value.get('before')) is not dict):raise ValueError('GUI update receipt changed')
    for identity in (value['before'],*([value['after']] if value['phase']!='prepared' else [])):
        if (type(identity) is not dict or set(identity)!={'root','data','webpage','rc','manifest_sha256','page_sha256','rc_sha256'}
            or any(type(v) is not str for v in identity.values())
            or any(not Path(identity[k]).is_absolute() or '..' in Path(identity[k]).parts for k in ('root','data','webpage','rc'))
            or any(len(identity[k])!=64 or any(c not in '0123456789abcdef' for c in identity[k]) for k in ('manifest_sha256','page_sha256','rc_sha256'))):
            raise ValueError('GUI update source identity changed')
    if value['phase']!='prepared':
        previous_source=Path(value['previous_source'])
        if previous_source.parent!=Path(value['before']['root']).parent or not previous_source.name.startswith('.dnsalias-previous-'):
            raise ValueError('GUI update previous-source identity changed')
    return previous


def update_ready(update):
    if (update.path/update.PENDING).exists():raise ValueError('pending GUI update requires inspection')
    record=update_record(update)
    if record is not None and record['checkpoint']['phase']!='complete':raise ValueError('incomplete GUI update requires inspection; never replay')


def _update_idle(journal):
    with UpdateFile(journal.path,expected_uid=journal.uid) as update:update_ready(update)


@guarded(mode='write')
def prepare_upgrade(*,update,journal,metadata,config,codec,config_guard,reload_guard,root,data,webpage,rc,candidate_sha256):
    _store(journal,metadata);native._guards(config_guard,reload_guard);update_ready(update)
    if type(update) is not UpdateFile or update.path!=journal.path or update.uid!=0:raise ValueError('matching native GUI update store required')
    entry=native._config(config,metadata);identity=_identity(root,data,webpage,rc);record=_record(journal);previous=journal.read()
    if record is None or record['phase']!='complete' or record['identity']!=identity or (journal.path/journal.PENDING).exists():raise ValueError('complete unchanged GUI setup required before update')
    if not manage.verify_ui(root,data,webpage) or serviceboot.registration(root,data,rc) is None:raise ValueError('owned page and service required before update')
    if any((Path(data)/n).exists() or (Path(data)/n).is_symlink() for n in ('collector.pid','alias-service.pid','trial-launch.json','trial-prepare-request','observation-prepare-request','hook-trial')):
        raise ValueError('stop owners and retire hook operation before GUI update')
    from dnsalias.webupgrade import ready as web_ready
    from dnsalias.policydelete import ready as delete_ready
    web_ready(root,data);delete_ready(data)
    current=codec.decode(_read(config,entry,time.monotonic()+1))['configuration'];view=plan.inspect(current)
    if not all(view.get(k) for k in ('registered','menu_present','service_present')):raise ValueError('complete owned native metadata required before update')
    prior=native._previous(metadata,entry[0])
    if prior is None or prior['checkpoint']['phase']!='installed':raise ValueError('completed native GUI metadata required before update')
    value={'format':UpdateFile.PAYLOAD_FORMAT,'phase':'prepared','before':identity,'candidate_sha256':candidate_sha256,
        'setup_before_sha256':previous['file_sha256'],'configuration_before_sha256':hashlib.sha256(_read(config,entry,time.monotonic()+1)).hexdigest()}
    prior_update=update_record(update);digest=update.save(value,expected_digest=prior_update['file_sha256'] if prior_update else None)
    return {'update_digest':digest,'before':identity}


@guarded(mode='write')
def finish_upgrade(*,update,journal,metadata,config,codec,config_guard,reload_guard,root,data,webpage,rc,expected_update_digest,candidate_sha256,previous_source):
    _store(journal,metadata);native._guards(config_guard,reload_guard);entry=native._config(config,metadata)
    record=update_record(update)
    if (record is None or record['file_sha256']!=expected_update_digest or record['checkpoint']['phase']!='prepared'
        or (update.path/update.PENDING).exists() or record['checkpoint']['candidate_sha256']!=candidate_sha256):raise ValueError('unchanged prepared GUI update required; inspect without replay')
    value=record['checkpoint'];setup=journal.read()
    if setup is None or setup['file_sha256']!=value['setup_before_sha256'] or _record(journal)!= {'format':journal.PAYLOAD_FORMAT,'phase':'complete','identity':value['before']}:
        raise ValueError('prior GUI setup changed during source update')
    identity=_identity(root,data,webpage,rc);manifest,_=bootstrap.runtime(root,data)
    if manifest.get('artifact_sha256')!=candidate_sha256:raise ValueError('updated runtime differs from selected candidate')
    if any(identity[k]!=value['before'][k] for k in ('root','data','webpage','rc','rc_sha256')):raise ValueError('update target or service contract changed')
    if not manage.verify_ui(root,data,webpage) or serviceboot.registration(root,data,rc) is None:raise ValueError('updated page/service readback differs')
    metadata_view=native.inspect(journal=metadata,config=config,codec=codec)
    if not all(metadata_view['registration'].get(k) for k in ('registered','menu_present','service_present')) or metadata_view['pending_receipt_present'] or metadata_view['pending_configuration_present']:
        raise ValueError('native metadata changed during GUI update')
    value.update(phase='source_replaced',after=identity,previous_source=str(previous_source))
    digest=update.save(value,expected_digest=expected_update_digest)
    journal.save({'format':journal.PAYLOAD_FORMAT,'phase':'complete','identity':identity},expected_digest=setup['file_sha256'])
    value['phase']='complete';update.save(value,expected_digest=digest)
    return {'gui_updated':True,'configuration_sha256_unchanged':hashlib.sha256(_read(config,entry,time.monotonic()+1)).hexdigest()==value['configuration_before_sha256'],
        'enabled':metadata_view['registration']['enabled'],'services_started':False,'rules_changed':False}


def _identity(root,data,webpage,rc):
    root,data,webpage,rc=map(Path,(root,data,webpage,rc))
    if webpage.name!='dnsalias_status.php' or rc.name!='dnsalias.sh':raise ValueError('fixed native GUI/service filenames required')
    for path in (root,data,webpage.parent,rc.parent):bootstrap.directory(path)
    manifest,source_hash=bootstrap.runtime(root,data);manage.verify(root,data)
    service=serviceboot.registration(root,data,rc)
    return {'root':str(root),'data':str(data),'webpage':str(webpage),'rc':str(rc),'manifest_sha256':source_hash,
        'page_sha256':manifest['files']['web/dnsalias_status.php'],
        'rc_sha256':service['sha256'] if service else hashlib.sha256(serviceboot.body(root)).hexdigest()}


def _store(journal,metadata):
    if (type(journal) is not SetupFile or type(metadata) is not native.RegistrationFile or journal.path!=metadata.path
        or journal.uid!=0 or metadata.uid!=0 or not sys.platform.startswith('freebsd') or os.geteuid()!=0):
        raise ValueError('native root and one private installer setup store required')


def _record(journal):
    previous=journal.read()
    if previous is None:return None
    value=previous['checkpoint']
    if (set(value)!={'format','phase','identity'} or value['format']!=journal.PAYLOAD_FORMAT
        or value['phase'] not in ('prepared','settings_published','rc_created','ui_created','complete',
            'migration_prepared','migration_registered',
            'remove_prepared','metadata_removed','service_removed','ui_removed','removed')
        or type(value['identity']) is not dict or set(value['identity'])!={'root','data','webpage','rc','manifest_sha256','page_sha256','rc_sha256'}
        or any(type(v) is not str for v in value['identity'].values())
        or any(not Path(value['identity'][key]).is_absolute() or '..' in Path(value['identity'][key]).parts for key in ('root','data','webpage','rc'))
        or any(len(value['identity'][key])!=64 or any(c not in '0123456789abcdef' for c in value['identity'][key]) for key in ('manifest_sha256','page_sha256','rc_sha256'))):raise ValueError('GUI setup receipt changed')
    return value


@guarded(mode='write')
def review_migration(*,config,codec,config_guard,reload_guard,root,data,webpage,rc):
    """Read-only proof for an explicitly selected, stopped legacy deployment.

    Retain either exact shipped service wrapper; do not reinterpret or repair
    resolver hooks, execute rc scripts, reset Enable or seed firewall rules.
    """
    native._guards(config_guard,reload_guard)
    root,data,webpage,rc=map(Path,(root,data,webpage,rc));identity=_identity(root,data,webpage,rc)
    if type(config) is not SourceAudit or config.state!='qualified' or len(config.files)!=1 or type(codec) is not NativeConfigCodec:
        raise ValueError('one qualified native configuration and converter required')
    entry=config.files[0];spec=entry[0]
    if spec.name!='firewall_config' or Path(spec.path).name!='config.xml' or spec.modes!=(0o600,) or spec.uid!=0:
        raise ValueError('private root native config.xml required for legacy migration')
    if any((data/n).exists() or (data/n).is_symlink() for n in ('collector.pid','alias-service.pid','trial-launch.json',
        'trial-prepare-request','observation-prepare-request','hook-trial')):
        raise ValueError('stop owners and retire hook operation before legacy migration')
    from dnsalias.webupgrade import ready as web_ready
    from dnsalias.policydelete import ready as delete_ready
    web_ready(root,data);delete_ready(data)
    raw=_read(config,entry,time.monotonic()+1);planned=plan.migrate(codec.decode(raw)['configuration'])
    # File markers, modes, links and exact installed source all participate in
    # the review. Merely finding matching native menu/service rows is not proof.
    # Version169's source updater published the authenticated page as0644;
    # newer installers use0600. Both are root-owned and never group/world
    # writable. This explicit migration accepts only those shipped modes.
    specs=[SourceSpec('legacy_'+str(i),str(path),0,0,modes,limit) for i,(path,modes,limit) in enumerate((
        (webpage,(0o600,0o644),1024*1024),(rc,(0o755,),8192),(data/'UI.json',(0o600,),4096),(data/'SERVICE.json',(0o600,),4096)))]
    with SourceAudit(specs,ancestor_uids=(0,)) as files:
        if not manage.verify_ui(root,data,webpage) or serviceboot.registration(root,data,rc) is None:
            raise ValueError('exact owned legacy UI and service required; no matching-file adoption')
        markers={name:hashlib.sha256((data/name).read_bytes()).hexdigest() for name in ('UI.json','SERVICE.json')}
        files.audit()
    value={'format':'dnsalias-legacy-gui-review-1','identity':identity,'configuration_sha256':hashlib.sha256(raw).hexdigest(),
        'markers':markers,'menu_added':planned['menu_added'],'enabled':planned['enabled']}
    digest=hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return value|{'review_sha256':digest,'configuration_changed':False,'services_started':False,'rules_created':False}


@guarded(mode='write')
def migrate(*,journal,metadata,config,codec,cache,config_guard,reload_guard,root,data,webpage,rc,review_sha256):
    """Attach installer receipts only after a fresh exact legacy review."""
    _store(journal,metadata);native._guards(config_guard,reload_guard);_update_idle(journal)
    entry=native._config(config,metadata)
    if (journal.read() is not None or (journal.path/journal.PENDING).exists()
        or native._previous(metadata,entry[0]) is not None):raise ValueError('existing GUI operation requires inspection; no migration replay')
    value=review_migration(config=config,codec=codec,config_guard=config_guard,reload_guard=reload_guard,
        root=root,data=data,webpage=webpage,rc=rc)
    if type(review_sha256) is not str or value['review_sha256']!=review_sha256:
        raise ValueError('unchanged explicit legacy review required before migration')
    record={'format':journal.PAYLOAD_FORMAT,'phase':'migration_prepared','identity':value['identity']}
    digest=journal.save(record,expected_digest=None)
    native.apply('migrate',journal=metadata,config=config,codec=codec,cache=cache,config_guard=config_guard,reload_guard=reload_guard,
        legacy_configuration_sha256=value['configuration_sha256'])
    record['phase']='migration_registered';digest=journal.save(record,expected_digest=digest)
    if (_identity(root,data,webpage,rc)!=value['identity'] or not manage.verify_ui(root,data,webpage)
        or serviceboot.registration(root,data,rc) is None):raise ValueError('legacy migration readback differs; inspect partial outcome')
    record['phase']='complete';journal.save(record,expected_digest=digest)
    return {'migrated':True,'configuration_changed':True,'enabled':value['enabled'],'menu_added':value['menu_added'],
        'services_started':False,'dns_changed':False,'rules_created':False,'legacy_files_preserved':True}


@guarded(mode='write')
def install(*,journal,metadata,config,codec,cache,config_guard,reload_guard,root,data,webpage,rc):
    _store(journal,metadata);native._guards(config_guard,reload_guard)
    _update_idle(journal)
    entry=native._config(config,metadata);root,data,webpage,rc=map(Path,(root,data,webpage,rc))
    identity=_identity(root,data,webpage,rc)
    previous=journal.read();record=_record(journal);prior_metadata=native._previous(metadata,entry[0])
    if (journal.path/journal.PENDING).exists() or record is not None and record['phase']!='removed':raise ValueError('existing GUI setup requires inspection; never replay')
    if record is None and prior_metadata is not None or record is not None and (prior_metadata is None or prior_metadata['checkpoint']['phase']!='removed'):
        raise ValueError('existing GUI metadata operation requires explicit migration')
    if record and any(record['identity'][key]!=identity[key] for key in ('root','data','webpage','rc')):
        raise ValueError('completed removal belongs to another GUI target')
    # Preflight all conflicts before publishing disabled settings. No matching
    # page/script/marker is adopted, including an owned prior partial setup.
    for path in (webpage,rc,data/'UI.json',data/'SERVICE.json'):
        if path.exists() or path.is_symlink():raise ValueError('existing GUI/service path requires inspection; no adoption')
    current=codec.decode(_read(config,entry,time.monotonic()+1))['configuration']
    if not plan.install(current)['changed']:raise ValueError('existing native GUI metadata requires explicit migration')
    value={'format':journal.PAYLOAD_FORMAT,'phase':'prepared','identity':identity}
    digest=journal.save(value,expected_digest=previous['file_sha256'] if previous else None)
    def save(phase):
        nonlocal digest
        native._guards(config_guard,reload_guard);value['phase']=phase;digest=journal.save(value,expected_digest=digest)
    native.apply('install',journal=metadata,config=config,codec=codec,cache=cache,config_guard=config_guard,reload_guard=reload_guard)
    save('settings_published')
    # Both guards remain held through file publication. Native configuration
    # readers cannot observe an enabled default before the saved off setting.
    serviceboot.enable(root,data,rc);save('rc_created')
    manage.install_ui(root,data,webpage);save('ui_created')
    if _identity(root,data,webpage,rc)!=identity or not manage.verify_ui(root,data,webpage) or serviceboot.registration(root,data,rc) is None:
        raise ValueError('GUI setup readback differs; inspect partial outcome')
    save('complete')
    return {'installed':True,'configuration_changed':True,'enabled':False,'service_started':False,
        'dns_changed':False,'aliases_created':False,'rules_created':False}


def _removal_ready(*,journal,metadata,config,codec,config_guard,reload_guard,root,data,webpage,rc,allow_populated):
    _store(journal,metadata);native._guards(config_guard,reload_guard)
    _update_idle(journal)
    entry=native._config(config,metadata);root,data,webpage,rc=map(Path,(root,data,webpage,rc))
    record=_record(journal);previous=journal.read();identity=_identity(root,data,webpage,rc)
    if record is None or record['phase']!='complete' or record['identity']!=identity or (journal.path/journal.PENDING).exists():
        raise ValueError('completed unchanged owned GUI setup required; inspect without replay')
    if not manage.verify_ui(root,data,webpage) or serviceboot.registration(root,data,rc) is None:
        raise ValueError('exact owned UI and service required before removal')
    if any((data/name).exists() or (data/name).is_symlink() for name in (
        'collector.pid','alias-service.pid','trial-launch.json','trial-prepare-request','observation-prepare-request','hook-trial','alias-registration')):
        raise ValueError('stop owners and retire alias/hook operations before GUI removal')
    from dnsalias.webupgrade import ready as web_ready
    from dnsalias.policydelete import ready as deletion_ready
    from dnsalias.plainsetup import ready as plain_ready
    web_ready(root,data);deletion_ready(data);plain_ready(data,removing=True)
    current=codec.decode(_read(config,entry,time.monotonic()+1))['configuration']
    package=current.get('installedpackages',{}).get('dnsalias',{})
    from dnsalias.policydelete import plan_all_stopped
    _,tables=plan_all_stopped(current,'','')
    if tables and not allow_populated:raise ValueError('remove DNS aliases and owned seed before GUI/package removal')
    # Validate the narrow configuration plan before any receipt/publication.
    plan.remove(current)
    prior=native._previous(metadata,entry[0])
    if prior is None or prior['checkpoint']['phase']!='installed':raise ValueError('completed GUI metadata installation required')
    return {'identity':identity,'previous':previous,'tables':tables}


@guarded(mode='write')
def review_remove(*,journal,metadata,config,codec,config_guard,reload_guard,root,data,webpage,rc):
    value=_removal_ready(journal=journal,metadata=metadata,config=config,codec=codec,config_guard=config_guard,reload_guard=reload_guard,root=root,data=data,webpage=webpage,rc=rc,allow_populated=True)
    return {'cleanup_tables':list(value['tables']),'configuration_changed':False}


@guarded(mode='write')
def remove(*,journal,metadata,config,codec,cache,config_guard,reload_guard,root,data,webpage,rc):
    """Detach the exact GUI only after stopped alias/seed cleanup completed."""
    value=_removal_ready(journal=journal,metadata=metadata,config=config,codec=codec,config_guard=config_guard,reload_guard=reload_guard,root=root,data=data,webpage=webpage,rc=rc,allow_populated=False)
    identity,previous=value['identity'],value['previous'];root,data,webpage,rc=map(Path,(root,data,webpage,rc))
    value={'format':journal.PAYLOAD_FORMAT,'phase':'remove_prepared','identity':identity}
    digest=journal.save(value,expected_digest=previous['file_sha256'])
    def save(phase):
        nonlocal digest
        native._guards(config_guard,reload_guard);value['phase']=phase;digest=journal.save(value,expected_digest=digest)
    native.apply('remove',journal=metadata,config=config,codec=codec,cache=cache,config_guard=config_guard,reload_guard=reload_guard)
    save('metadata_removed')
    serviceboot.disable(root,data,rc);save('service_removed')
    manage.remove_ui(root,data,webpage);save('ui_removed')
    for path in (rc.parent,webpage.parent,data):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    if any(path.exists() or path.is_symlink() for path in (rc,webpage,data/'UI.json',data/'SERVICE.json')):
        raise ValueError('GUI removal readback differs; inspect partial outcome')
    save('removed')
    return {'gui_removed':True,'configuration_changed':True,'services_started':False,'rules_changed':False,'dns_changed':False}


@guarded()
def inspect(*,journal,metadata,config,codec,root,data,webpage,rc):
    _store(journal,metadata);root,data,webpage,rc=map(Path,(root,data,webpage,rc));receipt=_record(journal)
    expected={key:str(path) for key,path in (('root',root),('data',data),('webpage',webpage),('rc',rc))}
    if receipt and any(receipt['identity'][k]!=v for k,v in expected.items()):raise ValueError('GUI setup target differs from its receipt')
    try:identity=_identity(root,data,webpage,rc);source={'verified':True,'matches_receipt':receipt is None or receipt['identity']==identity}
    except (ValueError,OSError) as exc:source={'verified':False,'error':str(exc)[:200]}
    try:ui={'owned':manage.verify_ui(root,data,webpage),'present':webpage.exists()}
    except (ValueError,OSError) as exc:ui={'owned':False,'present':webpage.exists(),'error':str(exc)[:200]}
    try:service={'owned':serviceboot.registration(root,data,rc) is not None,'present':rc.exists()}
    except (ValueError,OSError) as exc:service={'owned':False,'present':rc.exists(),'error':str(exc)[:200]}
    return {'receipt':receipt,'source':source,'ui':ui,'service':service,
        'metadata':native.inspect(journal=metadata,config=config,codec=codec),'pending_receipt_present':(journal.path/journal.PENDING).exists(),
        'automatic_recovery':False,'configuration_changed':False,'service_started':False,'rules_created':False}
