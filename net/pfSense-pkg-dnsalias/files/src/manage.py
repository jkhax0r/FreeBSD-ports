"""Own DNS Alias files/processes and its exact native service registration.

Policy/configuration and DNS/PF actions have their own explicit entry points.

Usage: python manage.py install package.zip | status | start --duration 600 |
       stop | uninstall [--purge-data]
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import signal
import stat
import subprocess
import time
import uuid
import zipfile
from dnsalias.lifecycle import current,guarded,process_command

ROOT=Path("/usr/local/libexec/dnsalias")
DATA=Path("/var/db/dnsalias")
WEBPAGE=Path("/usr/local/www/dnsalias_status.php")
MARKER="dnsalias-observation-v1"
DATA_FILES={"OWNER.json","events.sqlite","events.sqlite-journal","status.json","status.tmp","collector.pid","UI.json","identity-request"}
CHECKPOINT_FILES={"lease-checkpoint.json","lease-checkpoint.pending","lease-checkpoint.lock"}
CHECKPOINT_FILES.update({'policy-history.json','policy-history.pending','policy-history.lock'})
CHECKPOINT_FILES.update({'policies.json','policies.pending','policies.lock'})
CHECKPOINT_FILES.update({'web-update.json','web-update.pending','web-update.lock','web-update.operation.lock'})
CHECKPOINT_FILES.update({'policy-delete.json','policy-delete.pending','policy-delete.lock'})
CHECKPOINT_FILES.update({'plain-setup.json','plain-setup.pending','plain-setup.lock'})
CHECKPOINT_FILES.update({'plain-library.json','plain-library.pending','plain-library.lock'})
CHECKPOINT_FILES.update({'preferences-import.json','preferences-import.pending','preferences-import.lock'})
CHECKPOINT_FILES.update({'native-registry.json','native-registry.pending','native-registry.lock',
                         'native-migration.json','native-migration.pending','native-migration.lock'})
DATA_FILES.update(CHECKPOINT_FILES)
DATA_FILES.update({'alias-service.pid','alias-service.lock','alias-status.json','alias-status.tmp'})
DATA_FILES.update({'SERVICE.json','alias-last-session.json','alias-last-session.tmp'})
TRIAL_LAUNCH_FILES={'trial-profile.json','trial-launch.json','trial-last.json','trial-last.pending','trial-last.lock','trial-prepare-request','observation-prepare-request','trial-prepare-pending'}
DATA_FILES.update(TRIAL_LAUNCH_FILES)
TRIAL_DIRECTORY='hook-trial'
TRIAL_FILES={'OWNER.json','hook-trial.json','hook-trial.pending','hook-trial.lock'}
TRIAL_MARKER='dnsalias-owned-hook-trial-directory-1'
ALIAS_DIRECTORY='alias-registration'
ALIAS_MARKER='dnsalias-owned-alias-directory-1'
ALIAS_FILES={'OWNER.json','alias-install.json','alias-install.pending','alias-install.lock',
             'alias-remove.json','alias-remove.pending','alias-remove.lock'}


def verify_data_files(data,root=None):
    for p in data.iterdir():
        if p.name==ALIAS_DIRECTORY:
            if root is None:raise ValueError('explicit package root required for alias ownership')
            inspect_alias_directory(root,data)
            continue
        if p.name==TRIAL_DIRECTORY:
            if root is None:raise ValueError('explicit package root required for trial ownership')
            inspect_trial_directory(root,data)
            continue
        if p.is_symlink() or not p.is_file() or p.name not in DATA_FILES:
            raise ValueError("unexpected data directory content")
        if p.name=='identity-request':
            info=p.stat()
            if (info.st_size or info.st_nlink!=1 or info.st_uid!=data.stat().st_uid
                or stat.S_IMODE(info.st_mode)!=0o600):raise ValueError('unexpected metadata request file')
        if p.name in TRIAL_LAUNCH_FILES:
            info=p.lstat();directory=data.stat()
            if (os.name!='posix' or directory.st_uid!=os.geteuid() or stat.S_IMODE(directory.st_mode)!=0o700
                or info.st_uid!=directory.st_uid or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600
                or info.st_size>65536 or p.name in ('trial-last.lock','trial-prepare-request','observation-prepare-request') and info.st_size):
                raise ValueError('trial launch/profile file ownership changed')
        if p.name in CHECKPOINT_FILES:
            if os.name!='posix': raise ValueError('checkpoint file ownership requires POSIX qualification')
            directory=data.stat();item=p.stat()
            if directory.st_uid!=os.geteuid() or stat.S_IMODE(directory.st_mode)!=0o700:
                raise ValueError('checkpoint directory ownership changed')
            if item.st_uid!=directory.st_uid or stat.S_IMODE(item.st_mode)!=0o600 or item.st_nlink!=1:
                raise ValueError('checkpoint file ownership changed')
            if item.st_size>4*1024*1024 or p.name.endswith('.lock') and item.st_size:
                raise ValueError('unexpected checkpoint file size')


def inspect_trial_directory(root,data):
    """Read the optional private trial journal without accepting it as success."""
    path=Path(data)/TRIAL_DIRECTORY
    if not path.exists() and not path.is_symlink():return None
    safe_directory(path)
    if os.name!='posix':raise ValueError('native trial ownership required')
    for directory in (Path(data),path):
        info=directory.stat()
        if not directory.is_dir() or info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise ValueError('private owned data and trial directories required')
    names=set()
    for p in path.iterdir():
        item=p.lstat();names.add(p.name)
        if (p.name not in TRIAL_FILES or not stat.S_ISREG(item.st_mode) or item.st_nlink!=1
            or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600
            or item.st_size>65536 or p.name=='hook-trial.lock' and item.st_size):
            raise ValueError('trial content ownership changed')
    if 'OWNER.json' not in names or (path/'OWNER.json').stat().st_size>2048:
        raise ValueError('bounded trial ownership marker required')
    wanted={'owner':TRIAL_MARKER,'root':str(root),'data':str(data)}
    if json.loads((path/'OWNER.json').read_text())!=wanted:raise ValueError('trial ownership marker mismatch')
    from dnsalias.hooktrial import HookTrialFile
    with HookTrialFile(path,expected_uid=os.geteuid()) as journal:result=journal.read()
    return {'phase':result['checkpoint']['status']['phase'] if result else 'preparing',
        'pending_file':'hook-trial.pending' in names,'record':result,'files':sorted(names)}


def prepare_trial_directory(value,root=ROOT,data=DATA):
    """Inactive explicit preparation API; never called by install or the GUI.

    Caller coordinates the lifecycle. A partial creation remains for inspection;
    never replace or clear an existing trial, and never load/reload a hook here.
    """
    root,data=safe_directory(root),safe_directory(data);verify(root,data)
    if os.name!='posix':raise ValueError('native trial preparation required')
    info=data.stat()
    if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
        raise ValueError('private owned data directory required before trial preparation')
    from dnsalias.hooktrial import HookTrialFile,validate
    value=validate(value)
    if value['status']['phase']!='prepared':raise ValueError('new prepared trial intention required')
    path=data/TRIAL_DIRECTORY;path.mkdir(mode=0o700)
    with (path/'OWNER.json').open('xb') as marker:
        os.fchmod(marker.fileno(),0o600)
        marker.write(json.dumps({'owner':TRIAL_MARKER,'root':str(root),'data':str(data)},sort_keys=True).encode())
        marker.flush();os.fsync(marker.fileno())
    with HookTrialFile(path,expected_uid=os.geteuid()) as journal:checksum=journal.save(value,expected_digest=None)
    fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'prepared':True,'path':str(path),'file_sha256':checksum,'hook_changed':False,'reload_requested':False}


def trial_removal_ready(root,data,*,ancestor_uids=None):
    """Require a finished journal AND fresh original-source evidence to remove."""
    trial=inspect_trial_directory(root,data)
    if trial is None:return None
    if trial['phase']!='complete' or trial['pending_file']:
        raise RuntimeError('hook trial is incomplete or uncertain; inspect and finish restoration before package removal')
    from dnsalias.sourceaudit import SourceAudit,SourceSpec
    plan=trial['record']['checkpoint']['plan']
    specs=[SourceSpec(**(plan[name]|{'modes':tuple(plan[name]['modes'])})) for name in ('hook','config')]
    owners=tuple(dict.fromkeys((0,*[spec.uid for spec in specs]))) if ancestor_uids is None else ancestor_uids
    with SourceAudit(specs,ancestor_uids=owners) as sources:
        hashes=sources.audit()['sources']
        if hashes['selected_hook']!=plan['overlay']['original_sha256'] or hashes['resolver_config']!=plan['config_sha256']:
            raise RuntimeError('completed trial source changed; inspect before package removal')
    return trial


def retire_completed_trial(expected_digest,*,worker_stopped,root=ROOT,data=DATA,ancestor_uids=None):
    """Retire this caller's finished trial, preserving the installed package/DB.

    Only the owning supervisor calls this after its enrolled rollback child has
    exited and rule/feed writers are fenced. Never adopt a previous trial on
    startup. Any partial unlink or fsync failure requires explicit inspection.
    """
    if worker_stopped is not True or type(expected_digest) is not str or not re.fullmatch('[a-f0-9]{64}',expected_digest):
        raise ValueError('exited owned worker and exact completed journal digest required')
    root,data=safe_directory(root),safe_directory(data);verify(root,data)
    path=data/TRIAL_DIRECTORY
    from dnsalias.hooktrial import HookTrialFile
    with HookTrialFile(path,expected_uid=os.geteuid()) as journal:
        with journal._locked():
            # A live owner may carry its already-qualified resolver directory
            # UID through retirement (a root-owned hook can live there). Package
            # removal/recovery retains the original inferred-owner restriction.
            trial=trial_removal_ready(root,data,ancestor_uids=ancestor_uids)
            if trial is None or trial['record']['file_sha256']!=expected_digest:
                raise ValueError('completed journal changed before retirement')
            expected={'OWNER.json',HookTrialFile.NAME,HookTrialFile.LOCK}
            if set(trial['files'])!=expected:raise ValueError('completed journal contents changed')
            identities={}
            for name in expected:
                item=os.stat(name,dir_fd=journal.fd,follow_symlinks=False)
                identities[name]=(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            # All source evidence and every owned file were checked before any
            # deletion. Keep the marker/lock until the completed record is gone.
            for name in (HookTrialFile.NAME,'OWNER.json',HookTrialFile.LOCK):
                journal._directory()
                item=os.stat(name,dir_fd=journal.fd,follow_symlinks=False)
                if (item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)!=identities[name]:
                    raise ValueError('completed journal file changed during retirement')
                os.unlink(name,dir_fd=journal.fd)
            os.fsync(journal.fd);journal._directory();path.rmdir()
    fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'retired':True,'trial_id':trial['record']['checkpoint']['plan']['trial_id'],
            'journal_file_sha256':expected_digest,'telemetry_retained':True}


def inspect_alias_directory(root,data):
    """Read owned registration receipts; no phase label authorizes live writes."""
    path=Path(data)/ALIAS_DIRECTORY
    if not path.exists() and not path.is_symlink():return None
    safe_directory(path)
    if os.name!='posix':raise ValueError('native alias directory ownership required')
    for directory in (Path(data),path):
        item=directory.stat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700:
            raise ValueError('private owned alias and data directories required')
    names=set()
    for p in path.iterdir():
        item=p.lstat();names.add(p.name)
        if (p.name not in ALIAS_FILES or not stat.S_ISREG(item.st_mode) or item.st_nlink!=1
            or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o600
            or item.st_size>131072 or p.name.endswith('.lock') and item.st_size):
            raise ValueError('alias receipt directory content ownership changed')
    marker=path/'OWNER.json'
    if 'OWNER.json' not in names or marker.stat().st_size>2048:
        raise ValueError('bounded alias ownership marker required')
    if json.loads(marker.read_text())!={'owner':ALIAS_MARKER,'root':str(root),'data':str(data)}:
        raise ValueError('alias directory ownership marker mismatch')
    from dnsalias.aliasinstall import AliasInstallFile
    from dnsalias.aliasremove import AliasRemovalFile,bound_installation
    with AliasInstallFile(path,expected_uid=os.geteuid()) as journal:installation=journal.read()
    with AliasRemovalFile(path,expected_uid=os.geteuid()) as journal:removal=journal.read()
    if removal is not None:bound_installation(removal['checkpoint'],installation)
    return {'installation':installation,'removal':removal,'files':sorted(names),
        'pending_file':bool(names.intersection({'alias-install.pending','alias-remove.pending'}))}


def prepare_alias_directory(value,root=ROOT,data=DATA):
    """Inactive explicit API; preserve partial creation and never replace records."""
    root,data=safe_directory(root),safe_directory(data);verify(root,data)
    if os.name!='posix':raise ValueError('native alias preparation required')
    item=data.stat()
    if item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700:
        raise ValueError('private owned data directory required')
    from dnsalias.aliasinstall import AliasInstallFile,validate
    value=validate(value)
    if value['status']['phase']!='prepared':raise ValueError('new prepared alias installation required')
    path=data/ALIAS_DIRECTORY;path.mkdir(mode=0o700)
    with (path/'OWNER.json').open('xb') as marker:
        os.fchmod(marker.fileno(),0o600)
        marker.write(json.dumps({'owner':ALIAS_MARKER,'root':str(root),'data':str(data)},sort_keys=True).encode())
        marker.flush();os.fsync(marker.fileno())
    with AliasInstallFile(path,expected_uid=os.geteuid()) as journal:checksum=journal.save(value,expected_digest=None)
    fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'prepared':True,'path':str(path),'file_sha256':checksum,'configuration_changed':False}


def alias_removal_ready(root,data):
    """Retain recovery code until narrow removal and current file are verified.

    This guard covers the inactive unused-alias workflow, not writer shutdown or
    a PF capture coordinator. Later config changes conservatively need separate
    inspection even if unrelated. Never infer safety from a completed label alone.
    """
    aliases=inspect_alias_directory(root,data)
    if aliases is None:return None
    removed=aliases['removal']
    if aliases['pending_file'] or removed is None or removed['checkpoint']['status']['phase']!='complete':
        raise RuntimeError('alias registration is active or uncertain; finish narrow removal before package removal')
    from dnsalias.sourceaudit import SourceAudit,SourceSpec
    plan=removed['checkpoint']['plan'];spec=SourceSpec(**(plan['config']|{'modes':tuple(plan['config']['modes'])}))
    with SourceAudit([spec],ancestor_uids=tuple(dict.fromkeys((0,spec.uid)))) as sources:
        if sources.audit()['sources']['firewall_config']!=plan['after_file_sha256']:
            raise RuntimeError('configuration changed after alias removal; inspect before removing recovery code')
    return aliases


def retire_completed_aliases(installation_digest,removal_digest,*,root=ROOT,data=DATA):
    """Forget exact completed removal receipts, preserving collected statistics.

    Explicit inactive maintenance only. Stop the collector/owners first and
    serialize management for this installation. No configuration, PF, DNS or
    source change. Changed/currently installed definitions, pending outcomes,
    stale hashes and unexpected files are preserved. A partial deletion remains
    for inspection; this is never called by install/start or retried on error.
    """
    for value in (installation_digest,removal_digest):
        if type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value):
            raise ValueError('exact completed installation and removal digests required')
    root,data=safe_directory(root),safe_directory(data)
    import manage as manager
    from dnsalias.aliascoordinator import _idle
    _idle(manager,root,data)
    initial=alias_removal_ready(root,data)
    if initial is None:raise ValueError('completed alias removal receipts required')
    from dnsalias.aliasinstall import AliasInstallFile
    from dnsalias.aliasremove import AliasRemovalFile
    path=data/ALIAS_DIRECTORY
    with AliasInstallFile(path,expected_uid=os.geteuid()) as installation,AliasRemovalFile(path,expected_uid=os.geteuid()) as removal:
        with installation._locked(),removal._locked():
            _idle(manager,root,data);current=alias_removal_ready(root,data)
            expected={'OWNER.json',installation.NAME,installation.LOCK,removal.NAME,removal.LOCK}
            if (current is None or set(current['files'])!=expected
                or current['installation']['file_sha256']!=installation_digest
                or current['removal']['file_sha256']!=removal_digest):
                raise ValueError('completed alias receipts changed before retirement')
            identities={}
            for name in expected:
                item=os.stat(name,dir_fd=installation.fd,follow_symlinks=False)
                identities[name]=(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
            for name in (installation.NAME,removal.NAME,'OWNER.json',installation.LOCK,removal.LOCK):
                installation._directory();removal._directory()
                item=os.stat(name,dir_fd=installation.fd,follow_symlinks=False)
                if (item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)!=identities[name]:
                    raise ValueError('alias receipt file changed during retirement')
                os.unlink(name,dir_fd=installation.fd)
            os.fsync(installation.fd);installation._directory();path.rmdir()
    fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)
    return {'receipts_retired':True,'installation_sha256':installation_digest,'removal_sha256':removal_digest,
        'statistics_retained':True,'configuration_changed':False,'pf_changed':False,
        'source_changed':False,'automatic_retry':False}


def source_member(name):
    if name=='native/registry.php':return True
    if name in ('web/replyhealth.php','web/domainlabels.php','web/aliasinspect.php','web/preferences.php'):return True
    if name in ('native/confirmationkey.c','native/confirmationkey.cpython-311.so','native/confirmationkey.json'):return True
    if name in ('native/generation.c','native/generation.cpython-311.so','native/generation.json'):return True
    if name in ('native/replyextract.c','native/replyextract.cpython-311.so','native/replyextract.json'):return True
    if name in ('native/confirmation.c','native/confirmation.cpython-311.so','native/confirmation.json'):return True
    return name in ("README.md","manage.py","native/aliases.php","native/rules.php","native/policies.php","native/filterhook.php","native/configcodec.php","native/replywire.c","native/replywire.cpython-311.so","native/replywire.json") or bool(re.fullmatch(r"dnsalias/[a-z_]+\.py",name)) or name in ("web/dnsalias_status.php","web/view.php","web/console.php","web/style.php","web/client.php","web/clientview.php","web/inspectview.php","web/evidence.php","web/control.php","web/policies.php","web/destination.php","web/observation.php","web/capacity.php","web/lifecycle.php")


def digest(data): return hashlib.sha256(data).hexdigest()


def safe_directory(path):
    path=Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in owned path")
    return path


def unpack(payload):
    if len(payload)>1024*1024:
        raise ValueError("artifact too large")
    with zipfile.ZipFile(io.BytesIO(payload)) as z:
        names=z.namelist()
        if len(set(names))!=len(names) or len(names)>192 or sum(i.file_size for i in z.infolist())>2*1024*1024:
            raise ValueError("invalid archive size or duplicate members")
        for name in names:
            if not (name=="MANIFEST.json" or source_member(name)):
                raise ValueError("unexpected archive member")
        files={name:z.read(name) for name in names}
    manifest=json.loads(files.pop("MANIFEST.json"))
    if manifest.get("format")!=1 or manifest.get("mode")!="observation_only":
        raise ValueError("unsupported manifest")
    if set(files)!=set(manifest["files"]) or any(digest(b)!=manifest["files"][n] for n,b in files.items()):
        raise ValueError("artifact hash mismatch")
    if not {"manage.py","dnsalias/collector.py","dnsalias/__init__.py"}.issubset(files):
        raise ValueError("incomplete package")
    return files,manifest


def install(payload, root=ROOT, data=DATA):
    root,data=safe_directory(root),safe_directory(data)
    if root.exists():
        raise FileExistsError("existing source requires explicit verified upgrade; no overwrite")
    retained=data.exists()
    if retained:
        from dnsalias.webupgrade import ready
        ready(root,data)
        from dnsalias.plainsetup import ready as setup_ready
        setup_ready(data)
        if not data.is_dir() or json.loads((data/"OWNER.json").read_text())!={"owner":MARKER,"root":str(root)}:
            raise ValueError("existing data is not owned by this package")
        if (data/"collector.pid").exists():
            raise RuntimeError("retained data has a PID file; verify the prior collector first")
        if (data/'alias-service.pid').exists():raise RuntimeError('stop and verify alias feed before retained installation')
        if any((data/name).exists() for name in ('trial-launch.json','trial-prepare-request','observation-prepare-request')):raise RuntimeError('active or uncertain trial launch requires inspection before install')
        verify_data_files(data,root);trial_removal_ready(root,data);alias_removal_ready(root,data)
    if not root.parent.is_dir() or not data.parent.is_dir():
        raise ValueError("parent directories must already exist")
    files,manifest=unpack(payload)
    stage=root.parent/(".dnsalias-stage-"+uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    try:
        for name,body in files.items():
            p=stage/name
            p.parent.mkdir(parents=True,exist_ok=True)
            with p.open("xb") as f: f.write(body)
            os.chmod(p,0o600)
        manifest.update(owner=MARKER,artifact_sha256=digest(payload),installed_utc=time.time())
        (stage/"MANIFEST.json").write_text(json.dumps(manifest,indent=2))
        os.chmod(stage/"MANIFEST.json",0o600)
        if not retained:
            data.mkdir(mode=0o700)
            (data/"OWNER.json").write_text(json.dumps({"owner":MARKER,"root":str(root)}))
            os.chmod(data/"OWNER.json",0o600)
        # Rename only after all content is prepared. Parent is root-owned.
        stage.rename(root)
    except Exception:
        # Leave a partial stage for inspection; never delete uncertain content.
        raise
    return {"installed":True,"root":str(root),"data":str(data),"manifest":manifest,
            "configuration_changed":False,"startup_registered":False,"retained_data_reused":retained}


def verify(root=ROOT,data=DATA):
    root,data=safe_directory(root),safe_directory(data)
    manifest=json.loads((root/"MANIFEST.json").read_text())
    owner=json.loads((data/"OWNER.json").read_text())
    if manifest.get("owner")!=MARKER or owner!={"owner":MARKER,"root":str(root)}:
        raise ValueError("ownership marker mismatch")
    expected=set(manifest["files"])|{"MANIFEST.json"}
    actual=set()
    expected_dirs={PurePosixPath(name).parent.as_posix() for name in manifest["files"] if '/' in name}
    actual_dirs=set()
    for p in root.rglob("*"):
        if p.is_symlink(): raise ValueError("symlink in install")
        if p.is_file(): actual.add(p.relative_to(root).as_posix())
        elif p.is_dir(): actual_dirs.add(p.relative_to(root).as_posix())
        else: raise ValueError("unexpected installed file type")
    if actual!=expected or actual_dirs!=expected_dirs:
        raise ValueError("unexpected or missing installed file")
    for name,wanted in manifest["files"].items():
        if not source_member(name):
            raise ValueError("unsafe manifest path")
        if digest((root/name).read_bytes())!=wanted:
            raise ValueError("installed file modified: "+name)
    verify_data_files(data,root)
    registry_ready(root,data,manifest)
    return manifest


def registry_ready(root,data,manifest):
    """Validate external native entry ownership without adopting or repairing."""
    names=('native-registry.json','native-registry.pending','native-registry.lock',
           'native-migration.json','native-migration.pending','native-migration.lock')
    present=any(os.path.lexists(data/name) for name in names)
    if 'native/registry.php' not in manifest['files']:
        if present:raise ValueError('Native registry receipts require their qualified source')
        return None
    from dnsalias.registrymigration import ready
    from dnsalias.registryentry import ENTRY,RegistryFile,inspect
    ready(data);entry=ENTRY if root==ROOT else root.parent/'parse_config/dnsalias.inc'
    if os.path.lexists(entry) or any(os.path.lexists(data/name) for name in (RegistryFile.NAME,RegistryFile.PENDING)):
        return inspect(root,data,entry)
    return None


def _ui_pending(path):return path.with_name('.'+path.name+'.dnsalias-upgrade.pending')


def _atomic_ui_file(path,body,mode):
    pending=_ui_pending(path)
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,mode)
    try:
        os.fchmod(fd,mode);view=memoryview(body)
        while view:
            count=os.write(fd,view)
            if count<=0:raise OSError('short owned UI update write')
            view=view[count:]
        os.fsync(fd)
    finally:os.close(fd)
    os.replace(pending,path)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)


def counter_removal_ready(root,data,manifest=None):
    """Refuse before GUI/source mutation while optional RAM/cron is owned."""
    if root!=ROOT:return {'applicable':False}
    manifest=manifest or verify(root,data)
    if 'dnsalias/counterstore.py'not in manifest['files']:return {'applicable':False}
    from dnsalias.counterstore import CounterStore
    from dnsalias.countercron import CounterCron
    store=CounterStore();result=store.removable();schedule=CounterCron(store).inspect()
    if schedule['installed']:raise ValueError('Remove the owned counter checkpoint schedule before package removal')
    return {'applicable':True,'storage':result,'schedule':schedule}


def counter_upgrade_ready(root,data,old,candidate):
    if root!=ROOT or 'dnsalias/counterstore.py'not in old['files']:return {'applicable':False}
    if Path(__file__).resolve()!=root/'manage.py':
        # GUI publication executes the verified candidate from a private stage.
        # The counter controller deliberately accepts only installed canonical
        # code. Delegate this read-only preflight to that exact old source under
        # the parent's already-exclusive lifetime; never broaden its factory.
        held=current(root,data)
        if held is None or held.mode!='write' or not held.valid():
            raise ValueError('Exclusive source lifetime required for canonical counter preflight')
        request={'root':str(root),'data':str(data),'old':old,'candidate':candidate}
        raw=json.dumps(request,allow_nan=False)
        if len(raw)>262144:raise ValueError('Bounded counter upgrade manifest required')
        child=subprocess.run(['/usr/local/bin/python3.11','-B','-c',_COUNTER_UPGRADE_CHILD,str(held.life.fd)],
            input=raw,pass_fds=(held.life.fd,),capture_output=True,text=True,timeout=5)
        if child.returncode or child.stderr or len(child.stdout)>32768:
            raise ValueError('Canonical counter preflight failed; source retained: '+child.stderr[-500:])
        result=json.loads(child.stdout)
        if not held.valid() or type(result)is not dict or result.get('applicable')is not True:
            raise ValueError('Canonical counter preflight incomplete; source retained')
        return result
    from dnsalias.counterstore import CounterStore
    from dnsalias.countercron import CounterCron
    store=CounterStore();observed=store.inspect(include_database=False);schedule=CounterCron(store).inspect()
    if not observed['configured']or observed.get('phase')=='off':return counter_removal_ready(root,data,old)
    if observed.get('phase')!='active'or observed['mode']not in('ram','fallback_disk')or not schedule['installed']:
        raise ValueError('Incomplete counter storage/schedule requires inspection before upgrade')
    required={'dnsalias/countercheckpoint.py','dnsalias/counterstore.py','dnsalias/countercron.py','dnsalias/counterram.py'}
    if type(candidate.get('counter_ram_protocol'))is not int or candidate['counter_ram_protocol']!=1 or not required<=candidate['files'].keys():
        raise ValueError('Disable counter RAM storage before downgrading to a package without its compatible controller')
    return {'applicable':True,'active_storage_retained':True,'schedule_retained':True}


_COUNTER_UPGRADE_CHILD=r'''
import json,pathlib,sys
request=json.load(sys.stdin);root=pathlib.Path('/usr/local/libexec/dnsalias');data=pathlib.Path('/var/db/dnsalias')
assert request['root']==str(root)and request['data']==str(data)
sys.path.insert(0,str(root))
from dnsalias.lifecycle import InheritedLifetime
with InheritedLifetime(root,data,int(sys.argv[1])):
 import manage
 assert pathlib.Path(manage.__file__).resolve()==root/'manage.py'
 assert manage.verify(root,data)==request['old'],'installed source changed before counter preflight'
 result=manage.counter_upgrade_ready(root,data,request['old'],request['candidate'])
 assert manage.verify(root,data)==request['old'],'installed source changed during counter preflight'
 print(json.dumps(result))
'''


@guarded(mode='write')
def upgrade(payload,root=ROOT,data=DATA,webpage=WEBPAGE):
    """Replace verified source in place; retain aliases, configuration and DB.

    Stop owners first. Keep one verified prior source directory for explicit
    recovery; upgrades never remove/recreate the registered alias definitions.
    """
    root,data,webpage=map(safe_directory,(root,data,webpage))
    from dnsalias.webupgrade import ready
    ready(root,data)
    from dnsalias.policydelete import ready as deletion_ready
    deletion_ready(data)
    from dnsalias.plainsetup import ready as setup_ready
    old=verify(root,data)
    if any((data/name).exists() for name in ('collector.pid','alias-service.pid')):raise RuntimeError('stop and verify PID files before source upgrade')
    if owned_process(root,data) is not None:raise RuntimeError('stop collector before source upgrade')
    if root==ROOT:
        from dnsalias.aliasservice import process
        if process() is not None:raise RuntimeError('stop alias feed before source upgrade')
    if any((data/n).exists() for n in ('trial-launch.json','hook-trial')):raise RuntimeError('hook operation still active or uncertain')
    ui=verify_ui(root,data,webpage)
    if ui and any(_ui_pending(p).exists() or _ui_pending(p).is_symlink() for p in (webpage,data/'UI.json')):
        raise ValueError('pending owned UI publication requires inspection')
    files,manifest=unpack(payload)
    counter_upgrade_ready(root,data,old,manifest)
    setup_ready(data,candidate_base_sha256=manifest['files'].get('dnsalias/plainhook.py'))
    stage=root.parent/('.dnsalias-stage-'+uuid.uuid4().hex)
    previous=root.parent/('.dnsalias-previous-'+uuid.uuid4().hex)
    stage.mkdir(mode=0o700)
    for name,body in files.items():
        path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o600)
    manifest.update(owner=MARKER,artifact_sha256=digest(payload),installed_utc=time.time())
    (stage/'MANIFEST.json').write_text(json.dumps(manifest,indent=2));(stage/'MANIFEST.json').chmod(0o600)
    verify(root,data)
    root.rename(previous);stage.rename(root)
    if ui:
        body=(root/'web/dnsalias_status.php').read_bytes()
        _atomic_ui_file(webpage,body,0o644)
        _atomic_ui_file(data/'UI.json',json.dumps(ui_marker(root,webpage,body)).encode(),0o600)
    verify(root,data)
    return {'upgraded':True,'from':old.get('version'),'to':manifest.get('version'),'previous_source':str(previous),
            'aliases_preserved':True,'statistics_preserved':True,'services_started':False}


def owned_process(root=ROOT,data=DATA):
    pidfile=data/"collector.pid"
    if not pidfile.exists(): return None
    raw=pidfile.read_text().strip()
    if not raw.isdigit() or int(raw)<=1: raise ValueError("invalid collector PID")
    pid=int(raw)
    command=process_command(pid,timeout=3)
    if command is None:return None
    expected=(f"/usr/local/bin/python3.11 -B {root}/dnsalias/lifecycle.py collector --data-dir {data} --duration ",
              f"/usr/local/bin/python3.11 -B -m dnsalias.collector --data-dir {data} --duration ")
    if not any(command.startswith(prefix) and command[len(prefix):].isdigit() for prefix in expected):
        raise RuntimeError("PID belongs to another process; refusing signal")
    return pid


@guarded(control=True)
def start(duration=0,root=ROOT,data=DATA):
    verify(root,data)
    if type(duration) is not int or not 0<=duration<=86400:
        raise ValueError("duration must be 0 for continuous operation or 1..86400 seconds")
    if owned_process(root,data): raise RuntimeError("collector already running")
    subprocess.run(["/usr/sbin/daemon","-f","-p",str(data/"collector.pid"),
                    "/usr/local/bin/python3.11","-B",str(root/'dnsalias/lifecycle.py'),"collector",
                    "--data-dir",str(data),"--duration",str(duration)],cwd=root,check=True,timeout=5)
    return {"start_dispatched":True,"duration":duration,"requires_health_verification":True}


@guarded(control=True)
def stop(root=ROOT,data=DATA):
    verify(root,data)
    pid=owned_process(root,data)
    if pid is None: return {"stopped":True,"was_running":False}
    os.kill(pid,signal.SIGTERM)
    for _ in range(50):
        if owned_process(root,data) is None:
            return {"stopped":True,"pid":pid}
        time.sleep(0.1)
    raise RuntimeError("collector did not stop; no force kill attempted")


def ui_marker(root, webpage, body):
    return {"owner":MARKER,"root":str(root),"path":str(webpage),"sha256":digest(body)}


def verify_ui(root=ROOT,data=DATA,webpage=WEBPAGE):
    webpage=safe_directory(webpage)
    marker=data/"UI.json"
    if not marker.exists():
        return False
    body=(root/"web/dnsalias_status.php").read_bytes()
    if json.loads(marker.read_text()) != ui_marker(root,webpage,body):
        raise ValueError("UI ownership mismatch")
    if not webpage.is_file() or digest(webpage.read_bytes())!=digest(body):
        raise ValueError("UI source missing or modified")
    return True


@guarded(control=True)
def install_ui(root=ROOT,data=DATA,webpage=WEBPAGE):
    root,data,webpage=safe_directory(root),safe_directory(data),safe_directory(webpage)
    verify(root,data)
    if webpage.exists() or (data/"UI.json").exists():
        raise FileExistsError("existing UI requires inspection; no overwrite")
    if not webpage.parent.is_dir(): raise ValueError("web root missing")
    body=(root/"web/dnsalias_status.php").read_bytes()
    # Prepare privately, then publish a complete inode without overwriting any path.
    stage=root/(".ui-stage-"+uuid.uuid4().hex)
    with stage.open("xb") as f: f.write(body)
    os.chmod(stage,0o600)
    try:
        os.link(stage,webpage)
    finally:
        stage.unlink()
    marker=data/"UI.json"
    with marker.open("x") as f: json.dump(ui_marker(root,webpage,body),f)
    os.chmod(marker,0o600)
    verify_ui(root,data,webpage)
    return {"ui_installed":True,"path":str(webpage),"authenticated_by":"webConfigurator guiconfig.inc","configuration_changed":False}


@guarded(control=True)
def remove_ui(root=ROOT,data=DATA,webpage=WEBPAGE):
    verify(root,data)
    if verify_ui(root,data,webpage):
        webpage.unlink()
        (data/"UI.json").unlink()
        return {"ui_removed":True}
    return {"ui_removed":False,"reason":"no owned UI registered"}


@guarded(mode='write')
def uninstall(purge_data=False,root=ROOT,data=DATA,webpage=WEBPAGE):
    root,data=safe_directory(root),safe_directory(data)
    from dnsalias.webupgrade import ready
    ready(root,data)
    from dnsalias.policydelete import ready as deletion_ready
    deletion_ready(data)
    from dnsalias.plainsetup import ready as setup_ready
    setup_ready(data,removing=True)
    manifest=verify(root,data)
    counter_removal_ready(root,data,manifest)
    if any((data/name).exists() for name in ('trial-launch.json','trial-prepare-request','observation-prepare-request')):raise RuntimeError('active or uncertain trial launch requires inspection before package removal')
    trial=trial_removal_ready(root,data)
    aliases=alias_removal_ready(root,data)
    if (data/"collector.pid").exists():
        raise RuntimeError("PID file exists; stop and verify the collector before removal")
    if (data/'alias-service.pid').exists():raise RuntimeError('stop and verify alias feed before removal')
    from dnsalias import domainlabels
    label_review=domainlabels.inspect(data) if purge_data else None
    labels_retained=os.path.lexists(domainlabels.store_path(data)) and not purge_data
    has_ui=verify_ui(root,data,webpage)
    service_path=None
    if (data/'SERVICE.json').exists():
        from dnsalias.serviceboot import RC,_json,registration
        service_path=Path(_json(data/'SERVICE.json',4096)['path'])
        if root==ROOT and service_path!=RC:raise ValueError('native service path changed')
        registration(root,data,service_path)
    # Validate every file before removing any. Only exact owned paths are unlinked.
    native_configuration_changed=False
    if root==ROOT:
        from dnsalias.policydelete import operate as remove_policy_metadata
        seed_result=remove_policy_metadata(seed=True,remove=True,root=root,data=data)
        native_configuration_changed='deleted' in seed_result
        p=subprocess.run(['/usr/local/bin/php',str(root/'native/policies.php'),'unregister-service'],capture_output=True,text=True,timeout=5)
        if p.returncode:raise RuntimeError('Native service removal: '+p.stderr[-300:])
        removed_service=json.loads(p.stdout)['removed']
        if type(removed_service) is not bool:raise RuntimeError('Native service removal outcome unqualified')
        native_configuration_changed=native_configuration_changed or removed_service
    registry=registry_ready(root,data,manifest)
    if registry is not None and registry['installed']:
        if root==ROOT:
            from dnsalias.registrymigration import operate as retire_registry
            retired=retire_registry(action='retire',root=root,data=data)
            native_configuration_changed=native_configuration_changed or retired.get('configuration_changed',False)
        from dnsalias.registryentry import ENTRY,remove as remove_registry
        remove_registry(root,data,ENTRY if root==ROOT else root.parent/'parse_config/dnsalias.inc')
    if service_path is not None:
        from dnsalias.serviceboot import disable
        disable(root,data,service_path)
    if has_ui:
        webpage.unlink()
        (data/"UI.json").unlink()
    if purge_data:domainlabels.purge(data,label_review)
    for name in manifest["files"]: (root/name).unlink()
    (root/"MANIFEST.json").unlink()
    # verify() already matched every directory to this validated manifest.
    # Remove only those now-empty directories, including optional components.
    directories={PurePosixPath(name).parent.as_posix() for name in manifest['files'] if '/' in name}
    for name in sorted(directories,key=lambda value:len(PurePosixPath(value).parts),reverse=True):
        (root/name).rmdir()
    root.rmdir()
    if purge_data:
        if trial is not None:
            path=data/TRIAL_DIRECTORY
            for name in trial['files']:(path/name).unlink()
            path.rmdir()
        if aliases is not None:
            path=data/ALIAS_DIRECTORY
            for name in aliases['files']:(path/name).unlink()
            path.rmdir()
        for p in data.iterdir():p.unlink()
        data.rmdir()
    return {"uninstalled":True,"telemetry_retained":not purge_data,"domain_labels_retained":labels_retained,"configuration_changed":native_configuration_changed}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("action",choices=("install","upgrade","status","start","stop","uninstall","ui-install","ui-remove"))
    p.add_argument("artifact",nargs="?")
    p.add_argument("--duration",type=int,default=0)
    p.add_argument("--purge-data",action="store_true")
    a=p.parse_args()
    if a.action!='install' and current(ROOT,DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(ROOT/'dnsalias/lifecycle.py'),'operator','manage',*__import__('sys').argv[1:]])
    if a.action=="install": result=install(Path(a.artifact).read_bytes())
    elif a.action=="upgrade": result=upgrade(Path(a.artifact).read_bytes())
    elif a.action=="start": result=start(a.duration)
    elif a.action=="stop": result=stop()
    elif a.action=="uninstall": result=uninstall(a.purge_data)
    elif a.action=="ui-install": result=install_ui()
    elif a.action=="ui-remove": result=remove_ui()
    else:
        result={"manifest":verify(),"pid":owned_process(),
                "status":json.loads((DATA/"status.json").read_text()) if (DATA/"status.json").exists() else None}
    print(json.dumps(result,indent=2))


if __name__=="__main__": main()
