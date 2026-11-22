"""Own runtime installation independently of the native package's payload files.

pkg may ignore a failing uninstall script. Only installer/library/payload belong
to pkg; managed runtime and data never do. Existing installations stage updates.
Explicit apply requires stopped owners. Incomplete outcomes require inspection.
GUI publication is explicit. No service start/stop, DNS setup, rule creation,
external publication or forced expiry.
"""
import argparse
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import zipfile

FORMAT='dnsalias-package-owner-1'
RUNTIME_OWNER='dnsalias-observation-v1'
GUI_SOURCES = None
GUI_RUNTIME_SHA256 = None
CATALOG_SOURCES = None


def sha(raw):return hashlib.sha256(raw).hexdigest()


def directory(path,*,create=False,private=False):
    path=Path(path)
    if not path.is_absolute() or any(p in ('.','..') for p in path.parts) or not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path)):
        raise ValueError('canonical owned path required')
    current=Path('/')
    for part in path.parts[1:]:
        current/=part
        try:info=current.lstat()
        except FileNotFoundError:
            if not create:raise
            current.mkdir(mode=0o700);info=current.lstat()
        mode=stat.S_IMODE(info.st_mode);sticky=info.st_uid==0 and bool(mode&stat.S_ISVTX)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid() or (mode&0o022 and not sticky):raise ValueError('owned directory changed')
    if private and stat.S_IMODE(path.stat().st_mode)!=0o700:raise ValueError('private directory required')
    return path


def regular(path,limit):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info=os.fstat(fd);named=Path(path).lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=0o600
            or not 0<info.st_size<=limit or (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino)):
            raise ValueError('owned file metadata changed')
        raw=os.pread(fd,limit+1,0);after=os.fstat(fd);named_after=Path(path).lstat()
        fields=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_uid,i.st_mode,i.st_nlink)
        if len(raw)!=info.st_size or fields(info)!=fields(after) or fields(after)!=fields(named_after):raise ValueError('owned file changed during read')
        return raw
    finally:os.close(fd)


def catalog_assets(prefix):
    """Check only the installed optional metadata/bridge, never execute PHP."""
    if CATALOG_SOURCES is None:return None
    expected={'pkg/dnsalias.xml','pkg/dnsalias.inc','share/pfSense-pkg-dnsalias/info.xml'}
    if type(CATALOG_SOURCES) is not dict or set(CATALOG_SOURCES)!=expected:raise ValueError('catalog asset binding changed')
    for name,wanted in CATALOG_SOURCES.items():
        target=prefix/name;directory(target.parent)
        if sha(regular(target,65536))!=wanted:raise ValueError('catalog asset source changed')
    return {'verified':True,'files':len(expected)}


def automatic_gui(home,root,data,ledger):
    """A fresh GUI is disabled; a complete owned GUI preserves later settings."""
    current=runtime(root,data)
    adapter=gui_module(home,root,current)
    result=adapter.operate('install',prefix=home.parent.parent,installer_lock=ledger)
    if result.get('installed') and result.get('enabled') is not False:raise ValueError('fresh catalog setup was not disabled')
    result['native_registry']=(adapter.native_registry_setup if result.get('installed') else adapter.native_registry_inspect)(prefix=home.parent.parent)
    return result


def payload(path):
    raw=regular(path,4*1024*1024)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        items=archive.infolist()
        if len(items)>512 or len({i.filename for i in items})!=len(items) or sum(i.file_size for i in items)>16*1024*1024:raise ValueError('bounded unique payload required')
        for item in items:
            parts=Path(item.filename).parts
            if item.filename.startswith('/') or '..' in parts or item.file_size>8*1024*1024:raise ValueError('payload path/size refused')
        manifest=json.loads(archive.read('MANIFEST.json'))
        files=manifest.get('files')
        if manifest.get('format')!=1 or manifest.get('mode')!='observation_only' or type(files) is not dict:raise ValueError('qualified source artifact required')
        if set(files)|{'MANIFEST.json'}!={i.filename for i in items}:raise ValueError('payload inventory changed')
        for name,digest in files.items():
            if sha(archive.read(name))!=digest:raise ValueError('payload content changed')
        if not {'manage.py','dnsalias/__init__.py','dnsalias/collector.py'}.issubset(files):raise ValueError('incomplete runtime artifact')
    return raw,manifest


def runtime(root,data):
    directory(root,private=True);directory(data,private=True)
    if json.loads(regular(data/'OWNER.json',4096))!={'owner':RUNTIME_OWNER,'root':str(root)}:raise ValueError('runtime data is not owned')
    raw=regular(root/'MANIFEST.json',1024*1024);manifest=json.loads(raw);files=manifest.get('files')
    if manifest.get('owner')!=RUNTIME_OWNER or manifest.get('format')!=1 or type(files) is not dict or len(files)>512:raise ValueError('runtime manifest is not owned')
    actual=set()
    for parent,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:directory(Path(parent)/name)
        actual.update((Path(parent)/name).relative_to(root).as_posix() for name in names)
    if actual!=set(files)|{'MANIFEST.json'}:raise ValueError('runtime source inventory changed')
    total=0
    for name,wanted in files.items():
        if Path(name).is_absolute() or '..' in Path(name).parts:raise ValueError('runtime source path refused')
        body=regular(root/name,8*1024*1024);total+=len(body)
        if total>16*1024*1024 or sha(body)!=wanted:raise ValueError('runtime source changed')
    return manifest,sha(raw)


class Ledger:
    def __init__(self,path,identity):
        self.path=directory(path,create=True,private=True);self.identity=identity;self.lock=None
        if set(p.name for p in self.path.iterdir())-{'state.json','state.pending','lock','candidate.zip'}:raise ValueError('unknown installer ledger content')
        self.lock=os.open(self.path/'lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        i=os.fstat(self.lock)
        if not stat.S_ISREG(i.st_mode) or i.st_uid!=os.geteuid() or i.st_nlink!=1 or i.st_size or stat.S_IMODE(i.st_mode)!=0o600:raise ValueError('installer lock changed')
        fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def read(self):
        try:raw=regular(self.path/'state.json',65536)
        except FileNotFoundError:return None
        value=json.loads(raw)
        if type(value) is not dict or any(value.get(k)!=v for k,v in self.identity.items()):raise ValueError('installer ownership changed')
        return value

    def save(self,value):
        value=self.identity|value;raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
        if len(raw)>65536:raise ValueError('installer receipt size exceeded')
        fd=os.open(self.path/'state.pending',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600);view=memoryview(raw)
            while view:
                count=os.write(fd,view)
                if count<=0:raise OSError('short installer receipt write')
                view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        os.replace(self.path/'state.pending',self.path/'state.json')
        fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)

    def close(self):
        if self.lock is not None:os.close(self.lock);self.lock=None

    def snapshot(self,raw):
        path=self.path/'candidate.zip';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600);view=memoryview(raw)
            while view:
                count=os.write(fd,view)
                if count<=0:raise OSError('short candidate snapshot write')
                view=view[count:]
            os.fsync(fd)
        finally:os.close(fd)
        if sha(regular(path,4*1024*1024))!=sha(raw):raise ValueError('candidate snapshot differs')
        return path

    def retire_snapshot(self,path,expected):
        if path!=self.path/'candidate.zip' or sha(regular(path,4*1024*1024))!=expected:raise ValueError('owned candidate snapshot changed')
        path.unlink();fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)


def command(action,source,artifact,root,data,webpage):
    code='''import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[2]);import manage
action=sys.argv[1];root,data,web=map(Path,sys.argv[3:6]);artifact=Path(sys.argv[6])
try:
 if action=='probe':
  manage.verify(root,data)
  result={'busy':manage.owned_process(root,data) is not None or (data/'alias-service.pid').exists()}
 elif action=='install':result=manage.install(artifact.read_bytes(),root,data)
 elif action=='upgrade':result=manage.upgrade(artifact.read_bytes(),root,data,web)
 else:result=manage.uninstall(False,root,data,web)
 print(json.dumps({'ok':True,'result':{k:v for k,v in result.items() if k in ('busy','installed','upgraded','uninstalled','previous_source','telemetry_retained')}}))
except Exception as exc:
 print(json.dumps({'ok':False,'error':type(exc).__name__+': '+str(exc)[:350]}));raise SystemExit(1)
'''
    result=subprocess.run(['/usr/local/bin/python3.11','-B','-c',code,action,str(source),str(root),str(data),str(webpage),str(artifact)],capture_output=True,text=True,timeout=20)
    try:value=json.loads(result.stdout)
    except ValueError:raise RuntimeError('runtime manager outcome uncertain; inspect installer receipt') from None
    if result.returncode or not value.get('ok'):raise RuntimeError(value.get('error','runtime manager failed'))
    return value['result']


def gui_module(home,root,installed,*,allow_update=False,sources=None):
    """Load only exact installer library bytes bound by the native builder."""
    import types
    required={'gui.py','registration.py','registration_native.py','setup_native.py'}
    if type(GUI_SOURCES) is not dict or set(GUI_SOURCES)!=required:raise ValueError('this installer has no qualified GUI library')
    if installed is None or not allow_update and installed[0].get('artifact_sha256')!=GUI_RUNTIME_SHA256:
        raise ValueError('GUI installer runtime artifact differs; inspect source/package pairing')
    if sources is None:
        directory(home/'gui')
        if set(p.name for p in (home/'gui').iterdir())!=required:raise ValueError('GUI installer library inventory changed')
        bodies={name:regular(home/'gui'/name,131072) for name in GUI_SOURCES}
    else:
        if type(sources) is not dict or set(sources)!=required or any(type(v) is not bytes or len(v)>131072 for v in sources.values()):raise ValueError('complete frozen GUI source required')
        bodies=sources
    for name,wanted in GUI_SOURCES.items():
        if sha(bodies[name])!=wanted:raise ValueError('GUI installer library source changed')
    compiled={name:compile(body,str(home/'gui'/name),'exec') for name,body in bodies.items()}
    namespace='_dnsalias_installer_gui'
    if namespace in sys.modules:raise ValueError('GUI installer namespace already loaded')
    package=types.ModuleType(namespace);package.__path__=[str(home/'gui')];sys.modules[namespace]=package
    sys.modules[namespace+'.bootstrap']=sys.modules[__name__]
    sys.path.insert(0,str(root))
    # Execute the bytes just verified, without reopening filenames or creating
    # caches. Managed-runtime imports remain bound by runtime() and the exact
    # payload identity; hostile privileged writers are outside this protocol.
    for name in ('registration.py','registration_native.py','setup_native.py','gui.py'):
        key=namespace+'.'+name[:-3];module=types.ModuleType(key);module.__package__=namespace;module.__file__=str(home/'gui'/name)
        sys.modules[key]=module;exec(compiled[name],module.__dict__)
    result=sys.modules[namespace+'.gui'];result._installer_sources=bodies
    return result


def operate(action,prefix,*,review_sha256=None):
    if action!='gui-migrate' and review_sha256 is not None:raise ValueError('review digest is only valid for explicit legacy migration')
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native local root installer required')
    prefix=directory(prefix);home=prefix/'share/dnsalias'
    if Path(__file__).resolve()!=home/'bootstrap.py':raise ValueError('run the exact installed payload helper')
    directory(home);regular(home/'bootstrap.py',65536)
    catalog=None;catalog_error=None
    try:catalog=catalog_assets(prefix)
    except (ValueError,OSError) as exc:
        if action!='inspect':raise
        catalog_error=str(exc)[:200]
    automatic=action=='catalog-sync'
    if action in ('catalog-sync','catalog-resync','catalog-pre-remove') and catalog is None:raise ValueError('bound catalog archive required')
    if automatic:action='sync'
    artifact=home/'payload.zip';raw,candidate=payload(artifact)
    root=prefix/'libexec/dnsalias';data=Path('/var/db/dnsalias') if prefix==Path('/usr/local') else prefix/'var/db/dnsalias'
    ledger_path=data.with_name('dnsalias-package');webpage=prefix/'www/dnsalias_status.php'
    identity={'format':FORMAT,'prefix':str(prefix),'root':str(root),'data':str(data)}
    ledger=Ledger(ledger_path,identity)
    try:
        previous=ledger.read();installed=runtime(root,data) if root.exists() or root.is_symlink() else None
        if action=='inspect':return {'state':previous,'pending_receipt':(ledger.path/'state.pending').exists(),
            'candidate_snapshot_sha256':sha(regular(ledger.path/'candidate.zip',4*1024*1024)) if (ledger.path/'candidate.zip').exists() else None,
            'runtime_present':installed is not None,'runtime_version':installed[0]['version'] if installed else None,
            'candidate_version':candidate['version'],'candidate_sha256':sha(raw),'automatic_recovery':False,
            'gui_state_present':data.with_name('dnsalias-package-gui').exists(),'catalog':catalog,'catalog_error':catalog_error}
        if action=='gui-inspect' and previous and previous.get('action')=='gui_apply' and previous.get('phase') in ('apply_prepared','uncertain') and installed is not None:
            return gui_module(home,root,installed,allow_update=True).operate('inspect',prefix=prefix,installer_lock=ledger)
        if (ledger.path/'state.pending').exists() or (ledger.path/'candidate.zip').exists() or previous and previous.get('phase') not in ('installed','staged','retained','removed'):
            raise ValueError('incomplete installer outcome; inspect before any further action')
        common={'candidate_version':candidate['version'],'candidate_sha256':sha(raw)}
        if action=='catalog-pre-remove':
            if installed is None and previous and previous.get('phase')=='removed':
                return {'already_removed':True,'configuration_changed':False,'services_started':False}
            return {'retained':True,'reason':'Complete native GUI removal or explicit helper remove before deleting the catalog payload.',
                'configuration_changed':False,'services_started':False,'action_attempted':False}
        if action=='catalog-resync':
            if installed is None:raise ValueError('installed catalog runtime required')
            if installed[0].get('artifact_sha256')!=sha(raw):
                if (previous is None or previous.get('phase')!='staged' or previous.get('candidate_sha256')!=sha(raw)
                    or previous.get('baseline_sha256')!=installed[1]):raise ValueError('explicit unchanged staged catalog update required')
                return {'catalog_ready':False,'staged':True,'apply_required':True,'configuration_changed':False,'services_started':False,'rules_created':False}
            adapter=gui_module(home,root,installed)
            view=adapter.operate('inspect',prefix=prefix,installer_lock=ledger)
            if (not view.get('receipt') or view['receipt']['phase']!='complete' or not view['source'].get('matches_receipt')
                or not view['ui']['owned'] or not view['service']['owned']
                or not all(view['metadata']['registration'].get(k) for k in ('registered','menu_present','service_present'))
                or view['pending_receipt_present'] or view['metadata']['pending_receipt_present'] or view['metadata']['pending_configuration_present']
                or view.get('source_update',{}).get('pending')
                or (view.get('source_update',{}).get('record') and view['source_update']['record']['checkpoint']['phase']!='complete')):
                raise ValueError('complete unchanged catalog setup required; inspect without resync recovery')
            return {'catalog_ready':True,'configuration_changed':False,'services_started':False,'rules_created':False,
                'native_registry':adapter.native_registry_inspect(prefix=prefix)}
        if action.startswith('gui-'):
            if action not in ('gui-review','gui-inspect','gui-install','gui-remove','gui-migration-review','gui-migrate') or installed is None:raise ValueError('installed GUI action required')
            if action=='gui-install' and (previous is None or previous.get('phase')!='installed' or installed[0].get('artifact_sha256')!=sha(raw)):
                raise ValueError('current installed source/payload required before fresh GUI setup')
            adapter=gui_module(home,root,installed)
            result=adapter.operate(action[4:],prefix=prefix,installer_lock=ledger,**({'review_sha256':review_sha256} if action=='gui-migrate' else {}))
            if action=='gui-remove':ledger.save(common|{'phase':'removed','statistics_retained':data.exists()})
            return result
        if action=='sync' and installed:
            if installed[0].get('artifact_sha256')==sha(raw):
                ledger.save(common|{'phase':'installed','runtime_version':installed[0]['version'],'baseline_sha256':installed[1]})
                result={'already_current':True,'runtime_version':installed[0]['version']}
                if automatic:result['gui']=automatic_gui(home,root,data,ledger)
                return result
            ledger.save(common|{'phase':'staged','runtime_version':installed[0]['version'],'baseline_sha256':installed[1]})
            return {'staged':True,'apply_required':True,'runtime_version':installed[0]['version'],'candidate_version':candidate['version']}
        if action=='sync':
            if previous and previous.get('phase')!='removed' or data.exists() and previous is None:raise ValueError('retained/unknown installation requires inspection')
            directory(root.parent,create=True);directory(data.parent,create=True)
            ledger.save(common|{'phase':'install_prepared'})
            try:
                snapshot=ledger.snapshot(raw)
                command('install',snapshot,snapshot,root,data,webpage);current=runtime(root,data)
                if current[0]['artifact_sha256']!=sha(raw):raise ValueError('installed source readback differs')
                ledger.retire_snapshot(snapshot,sha(raw))
            except Exception as exc:
                ledger.save(common|{'phase':'uncertain','action':'install','error':str(exc)[:400]});raise
            ledger.save(common|{'phase':'installed','runtime_version':current[0]['version'],'baseline_sha256':current[1]})
            result={'installed':True,'service_started':False,'rules_created':False,'runtime_version':current[0]['version']}
            if automatic:result['gui']=automatic_gui(home,root,data,ledger)
            return result
        if action=='remove' and installed is None:
            if previous is not None and previous.get('phase')=='removed':return {'already_removed':True}
            raise ValueError('missing runtime requires inspection')
        if action not in ('apply','remove') or installed is None:raise ValueError('explicit installed apply/remove action required')
        gui_state=data.with_name('dnsalias-package-gui')
        if gui_state.exists() or gui_state.is_symlink():
            if action=='remove':
                adapter=gui_module(home,root,installed)
                try:result=adapter.operate('remove',prefix=prefix,installer_lock=ledger)
                except Exception as exc:
                    ledger.save(common|{'phase':'retained','reason':'GUI runtime removal refused or incomplete; inspect GUI receipt before retry',
                        'error':str(exc)[:400],'runtime_version':installed[0]['version'],'baseline_sha256':installed[1]})
                    raise
                ledger.save(common|{'phase':'removed','statistics_retained':data.exists()})
                return result
            if action=='apply':
                if (previous is None or previous.get('phase')!='staged' or previous.get('candidate_sha256')!=sha(raw)
                    or previous.get('baseline_sha256')!=installed[1]):raise ValueError('current staged candidate and unchanged GUI runtime required')
                return gui_module(home,root,installed,allow_update=True).apply_update(prefix=prefix,installer_lock=ledger,payload=raw)
            reason='GUI installer state retained; native update/removal orchestration is not yet qualified'
            return {'retained':True,'reason':reason,'runtime_version':installed[0]['version'],'action_attempted':False}
        if action=='apply' and (previous is None or previous.get('phase')!='staged' or previous.get('candidate_sha256')!=sha(raw) or previous.get('baseline_sha256')!=installed[1]):
            raise ValueError('current staged candidate and unchanged runtime required')
        if command('probe',root,artifact,root,data,webpage).get('busy'):
            if action=='remove':ledger.save(common|{'phase':'retained','reason':'runtime owners must be stopped','runtime_version':installed[0]['version'],'baseline_sha256':installed[1]})
            return {'retained':True,'reason':'runtime owners must be stopped','runtime_version':installed[0]['version'],'action_attempted':False}
        ledger.save(common|{'phase':action+'_prepared','baseline_sha256':installed[1]})
        try:
            snapshot=ledger.snapshot(raw) if action=='apply' else artifact
            result=command('upgrade' if action=='apply' else 'uninstall',root,snapshot,root,data,webpage)
            if action=='apply':
                current=runtime(root,data)
                if current[0]['artifact_sha256']!=sha(raw):raise ValueError('upgraded source readback differs')
                ledger.retire_snapshot(snapshot,sha(raw))
                ledger.save(common|{'phase':'installed','runtime_version':current[0]['version'],'baseline_sha256':current[1]})
                return {'upgraded':True,'runtime_version':current[0]['version'],'previous_source':result.get('previous_source')}
            if root.exists():raise ValueError('runtime removal outcome uncertain')
            ledger.save(common|{'phase':'removed','statistics_retained':data.exists()})
            return {'removed':True,'statistics_retained':data.exists()}
        except Exception as exc:
            ledger.save(common|{'phase':'uncertain','action':action,'error':str(exc)[:400]});raise
    finally:ledger.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('action',choices=('sync','inspect','apply','remove','gui-review','gui-inspect','gui-install','gui-remove','gui-migration-review','gui-migrate','catalog-sync','catalog-resync','catalog-pre-remove'));parser.add_argument('--prefix',default='/usr/local')
    parser.add_argument('--review-sha256',help='exact digest returned by the stopped legacy migration review')
    args=parser.parse_args()
    try:
        value=operate(args.action,Path(args.prefix),review_sha256=args.review_sha256);print(json.dumps(value))
        if value.get('retained'):raise SystemExit(1)
    except Exception as exc:
        print('DNS Alias runtime retained or outcome requires inspection: '+str(exc)[:450],file=sys.stderr);raise SystemExit(1)
