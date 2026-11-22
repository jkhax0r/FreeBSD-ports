"""Installed GUI adapter; invoked only by the verified bootstrap helper.

Normal prefix uses native config/locks. A nonproduction prefix derives every
writable path underneath itself for isolated qualification. Explicit removal
requires stopped ownership, removes only unused aliases and retains statistics. No service start,
DNS activation or automatic replay is exposed.
"""
from contextlib import ExitStack
import ast
import base64
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

import manage
from dnsalias.configcache import NativeConfigCache
from dnsalias.configcodec import NativeConfigCodec
from dnsalias.hookfile import _read
from dnsalias.reloadlock import ExclusiveConfigLock,SharedReloadLock
from dnsalias.sourceaudit import SourceAudit,SourceSpec
from dnsalias.lifecycle import Lifetime,LifecycleBusy
from . import bootstrap
from . import registration as plan
from . import registration_native as native
from . import setup_native as setup

FORMAT='dnsalias-gui-installer-owner-1'


def protocol_update_ready(old,candidate):
    # One explicit source transition: the 175 service adds the verified plain
    # base inode handoff inside the existing owned-overlay/new-boot branch.
    # Native rc.d bytes and checkpoint/GUI receipt formats stay identical.
    handoff=('e2217272801e8eadafbee8503966ec14dad5b14bbb9cfbf8a2fa3fe403566694',
             'ad7b6ab11c1be3142fd8ee68b1c031c34747189668a2f7e66e49a3a70ca9c95e')
    first_enable=('ad7b6ab11c1be3142fd8ee68b1c031c34747189668a2f7e66e49a3a70ca9c95e',
                  'a16c0d60e7687a55c7943eb7f51ead706b17da73fecefad2e62f19ea87288b17')
    # 198 -> 204 replaces only the rc Stop polling loop with stop(wait=True),
    # using the owned native process-exit watcher. Boot/hook recovery and
    # checkpoint/GUI receipt formats are unchanged; no reverse/foreign edge.
    native_stop=('a16c0d60e7687a55c7943eb7f51ead706b17da73fecefad2e62f19ea87288b17',
                 '67e1f8c4e1e372fcf4d67fa49b72ceee3ce0fd3d5e1c54f4de179ca0da9cceab')
    # Tighten prior-process inspection only. rc, checkpoints, hook admission
    # and boot identity branches are unchanged; no reverse/unknown transition.
    quiescent_process=('67e1f8c4e1e372fcf4d67fa49b72ceee3ce0fd3d5e1c54f4de179ca0da9cceab',
                       '96c456d08af5bac7c7caddcb1c2b05933e2d012bbbc4a80a21f4aca53c544da2')
    for name in ('dnsalias/serviceboot.py','dnsalias/checkpointfile.py'):
        before,after=old['files'].get(name),candidate['files'].get(name)
        if before==after:continue
        if name=='dnsalias/serviceboot.py' and (before,after) in (handoff,first_enable,native_stop,quiescent_process):continue
        raise ValueError('source update changes GUI/service protocol; explicit migration required')


def paths(prefix):
    prefix=Path(prefix);production=prefix==Path('/usr/local')
    data=Path('/var/db/dnsalias') if production else prefix/'var/db/dnsalias'
    return {'root':prefix/'libexec/dnsalias','data':data,'webpage':prefix/'www/dnsalias_status.php',
        'rc':prefix/'etc/rc.d/dnsalias.sh','configuration':Path('/cf/conf/config.xml') if production else prefix/'etc/pfsense/config.xml',
        'locks':Path('/tmp') if production else prefix/'var/run/dnsalias-native','store':data.with_name('dnsalias-package-gui')}


def _store(path,identity,*,create):
    allowed={'OWNER.json',setup.SetupFile.NAME,setup.SetupFile.PENDING,setup.SetupFile.LOCK,
        native.RegistrationFile.NAME,native.RegistrationFile.PENDING,native.RegistrationFile.LOCK,
        setup.UpdateFile.NAME,setup.UpdateFile.PENDING,setup.UpdateFile.LOCK}
    if not path.exists() and not path.is_symlink():
        if not create:return False
        bootstrap.directory(path.parent);path.mkdir(mode=0o700)
        fd=os.open(path/'OWNER.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            os.fchmod(fd,0o600);native._write(fd,json.dumps(identity,sort_keys=True,separators=(',',':')).encode())
        finally:os.close(fd)
        parent=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(parent)
        finally:os.close(parent)
    bootstrap.directory(path,private=True)
    if set(p.name for p in path.iterdir())-allowed:raise ValueError('unknown GUI installer state requires inspection')
    if json.loads(bootstrap.regular(path/'OWNER.json',4096))!=identity:raise ValueError('GUI installer ownership changed')
    return True


def operate(action,*,prefix,installer_lock,review_sha256=None):
    if action not in ('review','inspect','install','remove','migration-review','migrate'):raise ValueError('explicit GUI lifecycle action required')
    if action!='migrate' and review_sha256 is not None:raise ValueError('review digest is only valid for explicit legacy migration')
    prefix=bootstrap.directory(prefix);p=paths(prefix);root,data=p['root'],p['data']
    if (type(installer_lock) is not bootstrap.Ledger or installer_lock.lock is None
        or installer_lock.path!=data.with_name('dnsalias-package')):raise ValueError('held native installer lock required')
    held=os.fstat(installer_lock.lock);named=(installer_lock.path/'lock').lstat()
    if (held.st_dev,held.st_ino)!=(named.st_dev,named.st_ino):raise ValueError('native installer lock changed')
    identity={'format':FORMAT,'prefix':str(prefix),'root':str(root),'data':str(data),'configuration':str(p['configuration'])}
    with ExitStack() as lifetime:
        mode='write' if action in ('install','remove','migration-review','migrate') else 'read'
        try:lifetime.enter_context(Lifetime(root,data,mode=mode))
        except LifecycleBusy:
            if action!='install':raise
            # An already-complete setup can be inspected/no-op while workers
            # run; fresh setup/removal still needs an exclusive lifetime.
            lifetime.enter_context(Lifetime(root,data))
        manifest,source_hash=bootstrap.runtime(root,data);manage.verify(root,data)
        if manifest.get('artifact_sha256')!=bootstrap.GUI_RUNTIME_SHA256:raise ValueError('GUI runtime changed before lifecycle acquisition')
        cleanup=None
        if action=='remove':
            if 'dnsalias/counterstore.py'in manifest['files']:
                manage.counter_removal_ready(root,data,manifest)
            review=_native('remove-review',p,identity,manifest,source_hash)
            if review['cleanup_tables']:
                from dnsalias.policydelete import operate as delete_unused
                cleanup=delete_unused(remove=True,stopped=True,all_stopped=True,expected_tables=tuple(review['cleanup_tables']),
                    root=root,data=data,config=p['configuration'],locks=p['locks'])
        result=_native(action,p,identity,manifest,source_hash,update_arguments={'review_sha256':review_sha256} if action=='migrate' else None)
        if action!='remove':return result
        # Native config/filter guards have closed. Keep the source lifetime
        # exclusive across teardown so a cached/in-flight page cannot reenter.
        removed=manage.uninstall(False,root,data,p['webpage'])
        if root.exists() or root.is_symlink():raise ValueError('source removal outcome requires inspection')
        return result|{'runtime_removed':removed['uninstalled'],'statistics_retained':data.exists(),
            'unused_alias_cleanup':cleanup}


def _native(action,p,identity,manifest,source_hash,*,update_arguments=None):
    root,data=p['root'],p['data'];parser=Path('/etc/inc/xmlparse.inc');pi=parser.stat()
    with ExitStack() as stack:
        sources=stack.enter_context(SourceAudit([
            SourceSpec('config_codec',str(root/'native/configcodec.php'),0,0,(0o600,),65536),
            SourceSpec('native_xml_parser',str(parser),pi.st_uid,pi.st_gid,(stat.S_IMODE(pi.st_mode),),100000)],ancestor_uids=(0,)))
        codec=NativeConfigCodec(sources,helper_sha256=manifest['files']['native/configcodec.php']);stack.callback(codec.close)
        reload=SharedReloadLock(p['locks']/'filter.lock',expected_uid=0);guard=ExclusiveConfigLock(p['locks']/'config.lock',expected_uid=0)
        stack.callback(reload.close);stack.callback(guard.close);stack.enter_context(reload);stack.enter_context(guard)
        config=stack.enter_context(SourceAudit([SourceSpec('firewall_config',str(p['configuration']),0,0,(0o600,),2*1024*1024)],ancestor_uids=(0,)))
        current=codec.decode(_read(config,config.files[0],time.monotonic()+1))['configuration']
        if action in ('migration-review','migrate'):
            if _store(p['store'],identity,create=False):raise ValueError('existing GUI installer state requires inspection; no migration replay')
            reviewed=setup.review_migration(config=config,codec=codec,config_guard=guard,reload_guard=reload,
                root=root,data=data,webpage=p['webpage'],rc=p['rc'])
            if action=='migration-review':return reviewed
            if update_arguments is None or reviewed['review_sha256']!=update_arguments.get('review_sha256'):
                raise ValueError('unchanged explicit legacy review required before migration')
            _store(p['store'],identity,create=True)
        # Review has no provisioning side effect, even if this is not an
        # eligible namespace. It refuses matching legacy/unowned entries.
        if action=='review':
            if not plan.install(current)['changed']:raise ValueError('existing GUI metadata requires inspection, not new installation')
            for path in (p['webpage'],p['rc'],data/'UI.json',data/'SERVICE.json'):
                if path.exists() or path.is_symlink():raise ValueError('existing GUI/service path requires explicit migration')
            for directory in (p['webpage'].parent,p['rc'].parent):bootstrap.directory(directory)
            if _store(p['store'],identity,create=False):raise ValueError('existing GUI installer state requires inspection')
            return {'eligible':True,'source_manifest_sha256':source_hash,'configuration_changed':False,'service_started':False,'rules_created':False}
        if action=='inspect' and not _store(p['store'],identity,create=False):
            try:view=plan.inspect(current)
            except ValueError as exc:view={'error':str(exc)[:200]}
            return {'store_present':False,'registration':view,'automatic_recovery':False,'configuration_changed':False}
        if action in ('remove','remove-review','upgrade-prepare','upgrade-finish') and not _store(p['store'],identity,create=False):
            raise ValueError('completed owned GUI installer state required before removal')
        if action not in ('inspect','upgrade-finish') and _store(p['store'],identity,create=False):
            with setup.UpdateFile(p['store'],expected_uid=0) as existing_update:setup.update_ready(existing_update)
        if action=='install':
            if _store(p['store'],identity,create=False):
                journal=stack.enter_context(setup.SetupFile(p['store'],expected_uid=0));metadata=stack.enter_context(native.RegistrationFile(p['store'],expected_uid=0))
                view=setup.inspect(journal=journal,metadata=metadata,config=config,codec=codec,root=root,data=data,webpage=p['webpage'],rc=p['rc'])
                registration=view['metadata']['registration'];receipt=view['metadata']['receipt']
                if (view['receipt'] and view['receipt']['phase']=='complete' and view['source'].get('verified') and view['source'].get('matches_receipt')
                    and view['ui']['owned'] and view['service']['owned'] and not view['pending_receipt_present']
                    and not view['metadata']['pending_receipt_present'] and not view['metadata']['pending_configuration_present']
                    and receipt and receipt['phase']=='installed' and registration.get('registered') and registration.get('menu_present') and registration.get('service_present')):
                    return {'already_installed':True,'enabled':registration['enabled'],'configuration_changed':False,'service_started':False,'rules_created':False}
                if not (view['receipt'] and view['receipt']['phase']=='removed' and receipt and receipt['phase']=='removed'
                    and not view['ui']['present'] and not view['service']['present'] and not view['pending_receipt_present']
                    and not view['metadata']['pending_receipt_present'] and not view['metadata']['pending_configuration_present']):
                    raise ValueError('existing GUI setup is incomplete or changed; inspect without replay')
            if any((data/name).exists() for name in ('collector.pid','alias-service.pid')):
                raise ValueError('stop and verify runtime owners before GUI setup')
            # Refuse conflicts before creating an installer store as well as
            # before any native configuration publication.
            if not plan.install(current)['changed']:
                existing=(p['webpage'],p['rc'],data/'UI.json',data/'SERVICE.json')
                if not any(path.exists() or path.is_symlink() for path in existing):
                    raise ValueError('Restored DNS Alias settings have no owned GUI files or receipts. XML-only recovery requires explicit review; native metadata is not adopted.')
                raise ValueError('existing GUI metadata requires explicit migration')
            for path in (p['webpage'],p['rc'],data/'UI.json',data/'SERVICE.json'):
                if path.exists() or path.is_symlink():raise ValueError('existing GUI/service path requires explicit migration')
            for directory in (p['webpage'].parent,p['rc'].parent):bootstrap.directory(directory)
            _store(p['store'],identity,create=True)
        journal=stack.enter_context(setup.SetupFile(p['store'],expected_uid=0));metadata=stack.enter_context(native.RegistrationFile(p['store'],expected_uid=0))
        update=stack.enter_context(setup.UpdateFile(p['store'],expected_uid=0))
        args={'journal':journal,'metadata':metadata,'config':config,'codec':codec,'root':root,'data':data,'webpage':p['webpage'],'rc':p['rc']}
        if action=='inspect':
            value=setup.inspect(**args);value['source_update']={'record':setup.update_record(update),'pending':(p['store']/update.PENDING).exists()};return value
        if action in ('upgrade-prepare','upgrade-finish'):
            return (setup.prepare_upgrade if action=='upgrade-prepare' else setup.finish_upgrade)(**args,update=update,
                config_guard=guard,reload_guard=reload,**update_arguments)
        setup.update_ready(update)
        if action=='remove-review':return setup.review_remove(**args,config_guard=guard,reload_guard=reload)
        cache=NativeConfigCache(p['locks']/'config.cache',expected_uid=0,expected_gid=0);stack.callback(cache.close)
        if action=='migrate':return setup.migrate(**args,cache=cache,config_guard=guard,reload_guard=reload,**update_arguments)
        return (setup.remove if action=='remove' else setup.install)(**args,cache=cache,config_guard=guard,reload_guard=reload)


_UPDATE_CHILD=r'''
import base64,hashlib,io,json,os,pathlib,shutil,sys,tempfile,types,zipfile
request=json.load(sys.stdin);module=types.ModuleType('_dnsalias_frozen_bootstrap');module.__file__=request['bootstrap_path'];sys.modules[module.__name__]=module
source=base64.b64decode(request['bootstrap']);assert hashlib.sha256(source).hexdigest()==request['bootstrap_sha256'];exec(compile(source,module.__file__,'exec'),module.__dict__)
raw,manifest=module.payload(pathlib.Path(request['snapshot']));assert hashlib.sha256(raw).hexdigest()==request['candidate_sha256']==module.GUI_RUNTIME_SHA256
temporary=pathlib.Path(tempfile.mkdtemp(prefix='dnsalias-gui-update-',dir='/tmp'));temporary.chmod(0o700)
try:
 with zipfile.ZipFile(io.BytesIO(raw)) as archive:
  for name in archive.namelist():
   target=temporary/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(archive.read(name));target.chmod(0o600)
 sys.path.insert(0,str(temporary))
 from dnsalias.lifecycle import InheritedLifetime
 root,data=map(pathlib.Path,(request['root'],request['data']))
 with InheritedLifetime(root,data,int(sys.argv[1])):
  import manage
  result=manage.upgrade(raw,root,data,pathlib.Path(request['webpage']))
  installed=module.runtime(root,data)
  adapter=module.gui_module(pathlib.Path(request['home']),root,installed,sources={n:base64.b64decode(b) for n,b in request['gui'].items()})
  result['gui']=adapter.finish_update(prefix=pathlib.Path(request['prefix']),expected_update_digest=request['update_digest'],previous_source=result['previous_source'])
  result['native_registry']=adapter.native_registry_setup(prefix=pathlib.Path(request['prefix']))
  print(json.dumps(result))
finally:
 assert temporary.resolve().parent==pathlib.Path('/tmp') and temporary.name.startswith('dnsalias-gui-update-')
 shutil.rmtree(temporary)
'''


def apply_update(*,prefix,installer_lock,payload):
    prefix=bootstrap.directory(prefix);p=paths(prefix);root,data=p['root'],p['data'];home=prefix/'share/dnsalias'
    if type(installer_lock) is not bootstrap.Ledger or installer_lock.path!=data.with_name('dnsalias-package') or installer_lock.lock is None:
        raise ValueError('held native installer lock required for GUI update')
    raw,candidate=bootstrap.payload(home/'payload.zip')
    if raw!=payload or bootstrap.sha(raw)!=bootstrap.GUI_RUNTIME_SHA256:raise ValueError('current pinned GUI candidate required')
    with Lifetime(root,data,mode='write') as held:
        old,source_hash=bootstrap.runtime(root,data);manage.verify(root,data)
        protocol_update_ready(old,candidate)
        # Check optional storage through verified installed code before an
        # update journal or source stage is created. The staged child repeats
        # it under the same exclusive source lifetime before publication.
        if 'dnsalias/counterstore.py'in old['files']:
            manage.counter_upgrade_ready(root,data,old,candidate)
        body=bootstrap.regular(home/'bootstrap.py',65536);pins={}
        for node in ast.parse(body).body:
            if isinstance(node,ast.Assign):
                for target in node.targets:
                    if isinstance(target,ast.Name) and target.id in ('GUI_SOURCES','GUI_RUNTIME_SHA256'):pins[target.id]=ast.literal_eval(node.value)
        if pins!={'GUI_SOURCES':bootstrap.GUI_SOURCES,'GUI_RUNTIME_SHA256':bootstrap.GUI_RUNTIME_SHA256}:raise ValueError('installer changed before update capture')
        identity={'format':FORMAT,'prefix':str(prefix),'root':str(root),'data':str(data),'configuration':str(p['configuration'])}
        prepared=_native('upgrade-prepare',p,identity,old,source_hash,update_arguments={'candidate_sha256':bootstrap.GUI_RUNTIME_SHA256})
        snapshot=installer_lock.snapshot(raw)
        common={'candidate_version':candidate['version'],'candidate_sha256':bootstrap.GUI_RUNTIME_SHA256}
        installer_lock.save(common|{'phase':'apply_prepared','action':'gui_apply','baseline_sha256':source_hash})
        request={'bootstrap':base64.b64encode(body).decode(),'bootstrap_sha256':bootstrap.sha(body),'bootstrap_path':str(home/'bootstrap.py'),
            'gui':{n:base64.b64encode(b).decode() for n,b in _installer_sources.items()},'snapshot':str(snapshot),'candidate_sha256':bootstrap.GUI_RUNTIME_SHA256,
            'root':str(root),'data':str(data),'webpage':str(p['webpage']),'home':str(home),'prefix':str(prefix),'update_digest':prepared['update_digest']}
        try:
            child=subprocess.run(['/usr/local/bin/python3.11','-B','-c',_UPDATE_CHILD,str(held.life.fd)],input=json.dumps(request),capture_output=True,text=True,
                pass_fds=(held.life.fd,),timeout=25)
            if child.returncode or len(child.stdout)>262144:raise RuntimeError('GUI source update outcome requires inspection: '+child.stderr[-600:])
            result=json.loads(child.stdout);current,current_hash=bootstrap.runtime(root,data)
            with setup.UpdateFile(p['store'],expected_uid=0) as journal:record=setup.update_record(journal)
            if (not held.valid() or current.get('artifact_sha256')!=bootstrap.GUI_RUNTIME_SHA256 or record is None
                or record['checkpoint']['phase']!='complete' or record['checkpoint']['candidate_sha256']!=bootstrap.GUI_RUNTIME_SHA256):raise ValueError('GUI update readback incomplete')
            installer_lock.retire_snapshot(snapshot,bootstrap.GUI_RUNTIME_SHA256)
            installer_lock.save(common|{'phase':'installed','runtime_version':current['version'],'baseline_sha256':current_hash})
            return result
        except Exception as error:
            installer_lock.save(common|{'phase':'uncertain','action':'gui_apply','error':str(error)[:400]});raise


def finish_update(*,prefix,expected_update_digest,previous_source):
    from dnsalias.lifecycle import current
    prefix=bootstrap.directory(prefix);p=paths(prefix);root,data=p['root'],p['data'];held=current(root,data)
    if held is None or held.mode!='write':raise ValueError('inherited exclusive source lifetime required')
    manifest,source_hash=bootstrap.runtime(root,data)
    identity={'format':FORMAT,'prefix':str(prefix),'root':str(root),'data':str(data),'configuration':str(p['configuration'])}
    return _native('upgrade-finish',p,identity,manifest,source_hash,update_arguments={'expected_update_digest':expected_update_digest,
        'candidate_sha256':bootstrap.GUI_RUNTIME_SHA256,'previous_source':previous_source})


def native_registry_inspect(*,prefix):
    """An already-current package verifies registry state without recovery."""
    prefix=bootstrap.directory(prefix)
    if prefix!=Path('/usr/local'):return {'applicable':False,'reason':'isolated non-native prefix'}
    p=paths(prefix);root,data=p['root'],p['data']
    with Lifetime(root,data):
        manifest,unused=bootstrap.runtime(root,data);manage.verify(root,data)
        if 'native/registry.php' not in manifest['files']:return {'applicable':False,'reason':'legacy runtime'}
        from dnsalias.registryentry import inspect as inspect_registry
        entry=inspect_registry(root,data)
        if not entry['installed'] or not entry['matches_source']:raise ValueError('Native registry setup missing or changed; no resync recovery')
        php="require_once '/etc/inc/config.inc';if(config_get_path('installedpackages/dnsalias/native_alias_mode')!=='registered-v1'||($GLOBALS['dnsalias_registry_status']['state']??null)!=='registered')throw new RuntimeException('Native registry not active');echo 'registered';"
        value=subprocess.run(['/usr/local/bin/php','-r',php],capture_output=True,text=True,timeout=3)
        if value.returncode or value.stderr or value.stdout!='registered':raise ValueError('Native registry configuration unavailable; no resync recovery')
        return {'registered':True,'configuration_changed':False,'entry_changed':False,'automatic_recovery':False}


_REGISTRY_CHILD=r'''
import json,pathlib,sys
root=pathlib.Path('/usr/local/libexec/dnsalias');data=pathlib.Path('/var/db/dnsalias')
sys.path.insert(0,str(root))
from dnsalias.lifecycle import InheritedLifetime
with InheritedLifetime(root,data,int(sys.argv[1])):
 import manage
 manage.verify(root,data)
 from dnsalias.registryentry import provision,install
 from dnsalias.registrymigration import operate
 directory=provision(root,data);entry=install(root,data);migration=operate(root=root,data=data)
 print(json.dumps({'directory':directory,'entry':entry,'migration':migration,'service_started':False,'rules_created':False}))
'''


def native_registry_setup(*,prefix):
    """Fresh install or explicit stopped Apply; never a catalog resync repair."""
    prefix=bootstrap.directory(prefix)
    if prefix!=Path('/usr/local'):return {'applicable':False,'reason':'isolated non-native prefix'}
    p=paths(prefix);root,data=p['root'],p['data']
    with Lifetime(root,data,mode='write') as held:
        manifest,unused=bootstrap.runtime(root,data);manage.verify(root,data)
        if 'native/registry.php' not in manifest['files']:return {'applicable':False,'reason':'legacy runtime'}
        # Source Apply intentionally imports candidate code from a private
        # frozen staging directory. Native migration must execute the newly
        # installed canonical modules, without relaxing their path checks.
        # This installer-only child inherits the already-exclusive lifetime;
        # no extra process or IPC is added to DNS replies.
        value=subprocess.run(['/usr/local/bin/python3.11','-B','-c',_REGISTRY_CHILD,str(held.life.fd)],
            pass_fds=(held.life.fd,),capture_output=True,text=True,timeout=20)
        if value.returncode or value.stderr or len(value.stdout)>262144:
            raise ValueError('Native registry setup outcome requires inspection: '+value.stderr[-600:])
        result=json.loads(value.stdout)
        if not held.valid() or result.get('service_started') is not False or result.get('rules_created') is not False:
            raise ValueError('Native registry setup readback incomplete')
        return result
