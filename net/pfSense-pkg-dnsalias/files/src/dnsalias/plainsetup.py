"""Explicit first-hook file/configuration transactions; no default live paths.

Install publishes an exclusively created owned base and its native selector.
Unselect publishes only selector removal; the caller must then apply the native
resolver configuration, including its chroot/Python environment. Retire requires
a fresh authenticated no-Python runtime before removing the exact owned file and
marker. The installed root CLI requires explicit native resolver Save/Apply;
it has no service restart, PF change, foreign-hook adoption, automatic recovery
or UI setup action. An incomplete receipt requires inspection, never replay.
"""
from dataclasses import asdict
import hashlib
import json
import os
from contextlib import ExitStack
from pathlib import Path
import pwd
import stat
import sys
import time

from . import plainbootstrap as bootstrap
from .checkpointfile import CheckpointFile
from .configcache import NativeConfigCache
from .configcodec import NativeConfigCodec
from .hookfile import _read, _parents, _pending
from .reloadlock import ExclusiveConfigLock, SharedReloadLock
from .runtimecontrol import RuntimeControl,load_credentials,status_value
from .processwatch import ProcessLifetimeWatch
from .sourceaudit import SourceAudit, SourceSpec
from .lifecycle import current,guarded

NATIVE_CONTROL_PORT=953


class SetupFile(CheckpointFile):
    NAME='plain-setup.json';PENDING='plain-setup.pending';LOCK='plain-setup.lock'
    ENVELOPE_FORMAT='dnsalias-plain-setup-envelope-1';PAYLOAD_FORMAT='dnsalias-plain-setup-1'


def ready(data,*,removing=False,candidate_base_sha256=None):
    """Preserve the exact base on same-base upgrades; require retirement to remove."""
    from .plainlibrary import ready as library_ready
    library_ready(data,removing=removing)
    data=Path(data)
    if (data/SetupFile.PENDING).exists():raise ValueError('pending first-hook operation requires inspection')
    if (data/SetupFile.NAME).exists():
        with SetupFile(data,expected_uid=os.geteuid()) as journal:
            value=journal.read()['checkpoint']
            phase=value.get('phase')
            if phase in ('installed','retired'):
                _,value,spec=_record(journal,phase=phase)
        if phase=='installed' and not removing and candidate_base_sha256==value['source_sha256']:
            with SourceAudit([spec],ancestor_uids=tuple(dict.fromkeys((0,os.geteuid(),spec.uid)))) as hook:
                _hook(value,spec,hook)
            return
        if phase!='retired':
            raise ValueError('retire the owned plain hook before '+('uninstall' if removing else 'source upgrade')+'; inspect its operation receipt')


def _guards(config_guard,reload_guard):
    if (type(config_guard) is not ExclusiveConfigLock or type(reload_guard) is not SharedReloadLock
        or not config_guard.valid() or not reload_guard.valid() or config_guard.identity==reload_guard.identity):
        raise ValueError('distinct held native configuration and filter guards required')


def _cache(cache):
    if type(cache) is not NativeConfigCache or cache.state!='captured':raise ValueError('fresh qualified native cache required')
    cache._verify()


def _one(audit,label,basename):
    if type(audit) is not SourceAudit or audit.state!='qualified' or len(audit.files)!=1:
        raise ValueError('one fresh qualified source audit required')
    entry=audit.files[0];spec,parent,name,fd,metadata=entry
    modes=((0o600,),(0o644,),(0o600,0o644)) if label=='resolver_config' else ((0o600,),)
    if spec.name!=label or name!=basename or spec.modes not in modes:raise ValueError('explicit source identity required')
    audit.audit();return entry


def _spec(value):
    return asdict(value)|{'modes':list(value.modes)}


def _context(journal,config,codec,config_guard,reload_guard):
    if type(journal) is not SetupFile or type(codec) is not NativeConfigCodec:
        raise ValueError('owned setup receipt and qualified native XML codec required')
    _guards(config_guard,reload_guard)
    if (journal.path/'alias-service.pid').exists():raise ValueError('stop and verify the alias owner before first-hook changes')
    if (journal.path/SetupFile.PENDING).exists():raise ValueError('pending setup outcome requires inspection')
    entry=_one(config,'firewall_config','config.xml')
    if entry[0].uid!=journal.uid or os.geteuid() not in (0,journal.uid):raise ValueError('native config and receipt ownership differ')
    try:os.stat('config.xml.dnsalias-plain.pending',dir_fd=entry[1],follow_symlinks=False)
    except FileNotFoundError:pass
    else:raise ValueError('pending native configuration requires inspection')
    raw=_read(config,entry,time.monotonic()+1)
    return raw,codec.decode(raw)['configuration']


def _record(journal,*,phase):
    saved=journal.read()
    if saved is None or saved['checkpoint'].get('phase')!=phase:raise ValueError('unexpected setup phase; inspect before any further action')
    value=saved['checkpoint']
    if (set(value)!={'format','phase','source_sha256','hook','hook_identity','before_sha256','after_sha256'}
        or value.get('format')!=SetupFile.PAYLOAD_FORMAT):raise ValueError('setup receipt changed')
    bootstrap._source(value['source_sha256'])
    bootstrap._source(value['before_sha256']);bootstrap._source(value['after_sha256'])
    spec=SourceSpec(**(value['hook']|{'modes':tuple(value['hook']['modes'])}))
    if spec.name!='selected_hook' or Path(spec.path).name!=bootstrap.BASENAME+'.py' or spec.modes!=(0o600,):raise ValueError('owned hook receipt identity changed')
    identity=value.get('hook_identity')
    if type(identity) is not list or len(identity)!=2 or any(type(i) is not int for i in identity):raise ValueError('owned hook file identity missing')
    return saved,dict(value),spec


def _hook(value,spec,audit):
    entry=_one(audit,'selected_hook',bootstrap.BASENAME+'.py')
    if entry[0]!=spec or list(entry[4][:2])!=value['hook_identity'] or audit.hashes['selected_hook']!=value['source_sha256']:
        raise ValueError('owned base changed or replaced; no adoption')
    return entry


def exchange_owned(data,audit,manifest,*,overlay=None):
    """Transfer an owned base's inode only as part of our verified exchange.

    Matching bytes from an independently replaced file are still refused. The
    generic exchange pins the old inode and authenticates the new fd, pathname
    and bytes before invoking publication. No foreign-hook recovery is added.
    """
    from .hookfile import exchange
    entries=[e for e in audit.files if e[0].name=='selected_hook']
    if len(entries)!=1:raise ValueError('one inspected selected hook required')
    entry=entries[0];path=Path(entry[0].path);data=Path(data)
    if path.name!=bootstrap.BASENAME+'.py' or not os.path.lexists(data/SetupFile.NAME):
        return exchange(audit,manifest,overlay=overlay)
    with SetupFile(data,expected_uid=os.geteuid()) as journal:
        if os.path.lexists(data/SetupFile.PENDING):raise ValueError('pending plain hook receipt requires inspection')
        saved,value,spec=_record(journal,phase='installed')
        actual=entry[0]
        if (any(getattr(actual,k)!=getattr(spec,k) for k in ('name','path','uid','gid','modes'))
            or list(entry[4][:2])!=value['hook_identity'] or manifest['original_sha256']!=value['source_sha256']):
            raise ValueError('owned plain hook changed before exchange; no adoption')
        def publication(identity):
            value['hook_identity']=list(identity)
            journal.save(value,expected_digest=saved['file_sha256'])
        return exchange(audit,manifest,overlay=overlay,publication=publication)


def _write(fd,raw):
    view=memoryview(raw)
    while view:
        count=os.write(fd,view)
        if count<=0:raise OSError('short owned file write')
        view=view[count:]
    os.fsync(fd)


def _publish(audit,candidate,codec,cache,config_guard,reload_guard,*,before_commit):
    """Publish an already narrow candidate; retain pending bytes on any failure."""
    if type(cache) is not NativeConfigCache:raise ValueError('qualified native cache required')
    _guards(config_guard,reload_guard)
    entry=_one(audit,'firewall_config','config.xml');spec,parent,name,oldfd,metadata=entry
    converted=codec.encode(candidate)['xml'];raw=converted.encode() if isinstance(converted,str) else converted
    pending='config.xml.dnsalias-plain.pending'
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        os.fchown(fd,spec.uid,spec.gid);os.fchmod(fd,0o600);_write(fd,raw)
        identity=_pending(fd,parent,pending,spec,0o600)
        before_commit(hashlib.sha256(raw).hexdigest())
        _guards(config_guard,reload_guard);audit.audit();_parents(audit)
        _pending(fd,parent,pending,spec,0o600,identity)
        os.replace(pending,name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
    finally:os.close(fd)
    cache.invalidate()
    with SourceAudit([spec],ancestor_uids=audit.ancestor_uids) as fresh:
        observed=_read(fresh,fresh.files[0],time.monotonic()+1)
        if hashlib.sha256(observed).hexdigest()!=hashlib.sha256(raw).hexdigest() or codec.decode(observed)['configuration']!=candidate:
            raise ValueError('native config readback differs; inspect setup outcome')
    _guards(config_guard,reload_guard)
    return hashlib.sha256(raw).hexdigest()


def install(journal,config,resolver,base,codec,cache,config_guard,reload_guard,control,watch,*,library=None):
    """Create only a new owned file beside the inspected resolver config."""
    _cache(cache);before,current=_context(journal,config,codec,config_guard,reload_guard)
    previous=journal.read()
    if previous is not None and previous['checkpoint'].get('phase')!='retired':raise ValueError('existing setup operation requires inspection, not replay')
    runtime=bootstrap.inspect_factory(control,watch)
    entry=_one(resolver,'resolver_config','unbound.conf');parent=entry[1]
    source=_one(base,'plain_base','plainhook.py');body=_read(base,source,time.monotonic()+1)
    if source[0].uid!=journal.uid or len(body)>65536:raise ValueError('owned package base required')
    source_hash=hashlib.sha256(body).hexdigest()
    name=bootstrap.BASENAME+'.py';pending=name+'.dnsalias-setup.pending'
    for check in (name,pending):
        try:os.stat(check,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('existing hook or pending path cannot be adopted')
    plan=bootstrap.prepare(current,runtime,source_sha256=source_hash,hook_absent=True)
    if library is not None:
        from .plainlibrary import LibraryFile,install as library_install
        if type(library) is not LibraryFile or library.path!=journal.path:raise ValueError('matching library ownership store required')
        library_install(library,resolver)
        _guards(config_guard,reload_guard);resolver.audit();base.audit()
    # The generator's root-owned config is read-only input. The new Python
    # module must remain readable by the resolver after its privilege drop.
    identity=pwd.getpwnam('unbound')
    spec=SourceSpec('selected_hook',str(Path(entry[0].path).with_name(name)),identity.pw_uid,identity.pw_gid,(0o600,),65536)
    value={'format':SetupFile.PAYLOAD_FORMAT,'phase':'prepared','source_sha256':source_hash,'hook':_spec(spec),
        'before_sha256':hashlib.sha256(before).hexdigest()}
    digest=journal.save(value,expected_digest=previous['file_sha256'] if previous else None)
    def save(phase,after=None):
        nonlocal digest
        value['phase']=phase
        if after is not None:value['after_sha256']=after
        digest=journal.save(value,expected_digest=digest)
    resolver.audit();base.audit();_guards(config_guard,reload_guard)
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        os.fchown(fd,spec.uid,spec.gid);os.fchmod(fd,0o600);_write(fd,body)
        value['hook_identity']=list(_pending(fd,parent,pending,spec,0o600));save('hook_pending')
        resolver.audit();base.audit();_parents(resolver);_guards(config_guard,reload_guard)
        # link() is exclusive publication: even a newly appeared matching file
        # is refused rather than atomically overwritten. Both names are owned.
        os.link(pending,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False)
        if os.stat(name,dir_fd=parent,follow_symlinks=False).st_ino!=value['hook_identity'][1]:raise ValueError('hook link identity changed')
        os.unlink(pending,dir_fd=parent);os.fsync(parent)
        _pending(fd,parent,name,spec,0o600,tuple(value['hook_identity']));save('hook_created')
    finally:os.close(fd)
    def publication(after):
        resolver.audit();base.audit()
        again=bootstrap.inspect_factory(control,watch)
        if again['process_lifetime_id']!=runtime['process_lifetime_id'] or again['settings']!=runtime['settings']:raise ValueError('factory runtime changed before publication')
        save('config_prepared',after)
    with SourceAudit([spec],ancestor_uids=resolver.ancestor_uids) as created:
        # The intermediate receipt has no candidate hash until publication.
        _hook(value,spec,created)
        callback=publication
        def publication(after):
            created.audit();callback(after)
        _publish(config,plan['configuration'],codec,cache,config_guard,reload_guard,before_commit=publication)
        created.audit()
    save('installed')
    return {'installed':True,'hook':spec.path,'source_sha256':source_hash,'native_resolver_apply_required':True,'rules_changed':False}


def unselect(journal,config,hook,codec,cache,config_guard,reload_guard,control,watch):
    """Retain the base and ownership marker while native apply is pending."""
    _cache(cache);before,current=_context(journal,config,codec,config_guard,reload_guard)
    if not isinstance(control,RuntimeControl) or not isinstance(watch,ProcessLifetimeWatch):raise ValueError('qualified native runtime required')
    saved,value,spec=_record(journal,phase='installed');_hook(value,spec,hook)
    bootstrap.removal(current,source_sha256=value['source_sha256'])
    if {k:current['unbound'][k] for k in bootstrap.FIELDS if k in current['unbound']}!=bootstrap.FIELDS:raise ValueError('owned selector was already changed; inspect before unselect')
    runtime=control.capture(watch)
    if (runtime['settings']['module-config'] not in ('python iterator','validator python iterator')
        or runtime['settings']['python-script'] not in (bootstrap.BASENAME+'.py',spec.path)):
        raise ValueError('verified selected owned base runtime required')
    candidate=json.loads(json.dumps(current))
    for key in bootstrap.FIELDS:del candidate['unbound'][key]
    value['before_sha256']=hashlib.sha256(before).hexdigest()
    digest=saved['file_sha256']
    def publication(after):
        nonlocal digest
        hook.audit()
        again=control.capture(watch)
        if (again['settings']['module-config']!=runtime['settings']['module-config']
            or again['settings']['python-script']!=runtime['settings']['python-script']):raise ValueError('selected resolver runtime changed')
        value.update(phase='unselect_prepared',after_sha256=after)
        digest=journal.save(value,expected_digest=digest)
    _publish(config,candidate,codec,cache,config_guard,reload_guard,before_commit=publication)
    value['phase']='unselected';journal.save(value,expected_digest=digest)
    return {'unselected':True,'owned_file_retained':True,'native_resolver_apply_required':True,'rules_changed':False}


def retire(journal,config,hook,codec,cache,config_guard,reload_guard,control,watch):
    """Delete only the exact owned base after native unselection took effect."""
    _cache(cache);before,current=_context(journal,config,codec,config_guard,reload_guard)
    saved,value,spec=_record(journal,phase='unselected');entry=_hook(value,spec,hook)
    plan=bootstrap.removal(current,source_sha256=value['source_sha256'])
    if not plan['already_unselected']:raise ValueError('native configuration still selects Python')
    bootstrap.inspect_factory(control,watch)
    value.update(phase='retire_prepared',before_sha256=hashlib.sha256(before).hexdigest())
    digest=journal.save(value,expected_digest=saved['file_sha256'])
    hook.audit();_parents(hook);_guards(config_guard,reload_guard)
    if not watch.alive():raise ValueError('unselected resolver lifetime ended')
    os.unlink(entry[2],dir_fd=entry[1]);os.fsync(entry[1])
    def publication(after):
        nonlocal digest
        if not watch.alive():raise ValueError('unselected resolver lifetime ended')
        value.update(phase='retire_config_prepared',after_sha256=after)
        digest=journal.save(value,expected_digest=digest)
    _publish(config,plan['configuration'],codec,cache,config_guard,reload_guard,before_commit=publication)
    value['phase']='retired';journal.save(value,expected_digest=digest)
    return {'retired':True,'owned_file_removed':True,'rules_changed':False,'native_resolver_apply_required':False}


def _inspect_file(parent,name,limit):
    try:item=os.stat(name,dir_fd=parent,follow_symlinks=False)
    except FileNotFoundError:return None
    value={'device':item.st_dev,'inode':item.st_ino,'uid':item.st_uid,'gid':item.st_gid,'mode':oct(stat.S_IMODE(item.st_mode)),
        'links':item.st_nlink,'size':item.st_size,'regular':stat.S_ISREG(item.st_mode)}
    if not value['regular'] or item.st_nlink!=1 or not 0<=item.st_size<=limit:return value
    fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
    try:
        before=os.fstat(fd)
        if (before.st_dev,before.st_ino)!=(item.st_dev,item.st_ino):raise ValueError('inspection path changed')
        raw=os.pread(fd,limit+1,0);after=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        fields=lambda i:(i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_ctime_ns,i.st_nlink,i.st_mode,i.st_uid,i.st_gid)
        if fields(before)!=fields(after) or fields(after)!=fields(named) or len(raw)!=after.st_size:raise ValueError('inspection file changed')
        value['sha256']=hashlib.sha256(raw).hexdigest()
    finally:os.close(fd)
    return value


def inspect(journal,config,resolver,codec):
    """Read-only outcome evidence, with no finish/retry/recovery authority."""
    if type(journal) is not SetupFile or type(codec) is not NativeConfigCodec:raise ValueError('qualified setup evidence required')
    entry=_one(config,'firewall_config','config.xml');raw=_read(config,entry,time.monotonic()+1)
    current=codec.decode(raw)['configuration'];parent=_one(resolver,'resolver_config','unbound.conf')[1]
    paths={name:_inspect_file(parent,name,65536) for name in (bootstrap.BASENAME+'.py',bootstrap.BASENAME+'.py.dnsalias-setup.pending')}
    receipt=journal.read()
    package=current.get('installedpackages',{})
    if type(package) is dict:package=package.get('dnsalias',{})
    return {'receipt':None if receipt is None else receipt['checkpoint'],'current_config_sha256':hashlib.sha256(raw).hexdigest(),
        'selector':{k:current.get('unbound',{}).get(k) for k in bootstrap.FIELDS if k in current.get('unbound',{})},
        'ownership_marker_present':type(package) is dict and 'plain_hook_json' in package,
        'pending_receipt_present':(journal.path/SetupFile.PENDING).exists(),
        'pending_configuration':_inspect_file(entry[1],'config.xml.dnsalias-plain.pending',2*1024*1024),
        'files':paths,'automatic_recovery':False,'mutation_authorized':False}


def resolver_configuration_spec(path,*,resolver_uid,resolver_gid):
    """Native Apply creates root-owned files inheriting the chroot's group.

    Pin the observed qualified pair for SourceAudit's no-follow open/recheck.
    This accepts no foreign owner and does not change owned hook permissions.
    """
    info=Path(path).lstat();pair=(info.st_uid,info.st_gid)
    if pair not in ((0,0),(0,resolver_gid),(resolver_uid,resolver_gid)):
        raise ValueError('native resolver configuration owner refused')
    return SourceSpec('resolver_config',str(path),*pair,(0o600,0o644),2*1024*1024)


@guarded()
def operate(action,*,root=None,data=None,configuration=None,resolver_config=None,locks=None,control=None):
    """Installed local CLI adapter. Native resolver Apply is deliberately explicit.

    Optional paths/control support only caller-owned isolated native fixtures;
    the CLI exposes no target overrides. It cannot mount environments, restart
    DNS, change rules, finish incomplete operations or recover a foreign hook.
    """
    import manage
    if action not in ('review','install','inspect','unselect','retire'):raise ValueError('explicit first-hook action required')
    root=Path(root or manage.ROOT);data=Path(data or manage.DATA)
    cf=Path(configuration or '/cf/conf/config.xml');resolver_path=Path(resolver_config or '/var/unbound/unbound.conf');locks=Path(locks or '/tmp')
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0 or root!=Path(__file__).resolve().parents[1]:
        raise ValueError('installed native local root adapter required')
    manifest=manage.verify(root,data);uid,gid=os.geteuid(),os.getegid();unbound=pwd.getpwnam('unbound')
    parser=Path('/etc/inc/xmlparse.inc');parser_info=parser.stat()
    owners=tuple(dict.fromkeys((0,unbound.pw_uid)))
    with ExitStack() as stack:
        native=stack.enter_context(SourceAudit([SourceSpec('unbound_source','/etc/inc/unbound.inc',0,0,(0o644,),262144)],ancestor_uids=(0,)))
        if native.hashes['unbound_source']!='89e4a26dbab44ce31c23784541a6fb516dea4241642d682535ae22ffbf5945ba':raise ValueError('native resolver generator changed; first-hook integration requires qualification')
        sources=stack.enter_context(SourceAudit([
            SourceSpec('config_codec',str(root/'native/configcodec.php'),uid,gid,(0o600,),65536),
            SourceSpec('native_xml_parser',str(parser),parser_info.st_uid,parser_info.st_gid,(stat.S_IMODE(parser_info.st_mode),),100000)],ancestor_uids=(0,)))
        codec=NativeConfigCodec(sources,helper_sha256=manifest['files']['native/configcodec.php']);stack.callback(codec.close)
        reload=SharedReloadLock(locks/'filter.lock',expected_uid=uid);guard=ExclusiveConfigLock(locks/'config.lock',expected_uid=uid)
        stack.callback(reload.close);stack.callback(guard.close);stack.enter_context(reload);stack.enter_context(guard)
        config=stack.enter_context(SourceAudit([SourceSpec('firewall_config',str(cf),uid,gid,(0o600,),2*1024*1024)],ancestor_uids=(0,)))
        resolver=stack.enter_context(SourceAudit([resolver_configuration_spec(resolver_path,resolver_uid=unbound.pw_uid,resolver_gid=unbound.pw_gid)],ancestor_uids=owners))
        journal=stack.enter_context(SetupFile(data,expected_uid=uid))
        if action=='inspect':
            result=inspect(journal,config,resolver,codec)
            from .plainlibrary import LibraryFile
            if os.path.lexists(data/LibraryFile.NAME):
                with LibraryFile(data,expected_uid=0) as library:
                    receipt=library.read();result['runtime_library']=receipt['checkpoint'] if receipt else None
            result['runtime_library_pending']=os.path.lexists(data/LibraryFile.PENDING)
            return result
        if control is None:
            credentials=load_credentials(str(resolver_path.parent),expected_uid=unbound.pw_uid,expected_gid=unbound.pw_gid)
            control=RuntimeControl(credentials['context'],address='127.0.0.1',port=NATIVE_CONTROL_PORT,server_certificate_sha256=credentials['server_certificate_sha256'])
        if type(control) is not RuntimeControl:raise ValueError('qualified local resolver control required')
        status=(status_value if action=='unselect' else bootstrap.factory_status)(control._read(None,time.monotonic()+1))
        watch=stack.enter_context(ProcessLifetimeWatch(status['pid']))
        native.audit()
        if action=='review':
            before,current=_context(journal,config,codec,guard,reload)
            if journal.read() is not None and journal.read()['checkpoint'].get('phase')!='retired':raise ValueError('existing setup receipt requires inspection')
            source_hash=manifest['files']['dnsalias/plainhook.py']
            name=bootstrap.BASENAME+'.py'
            for path in (name,name+'.dnsalias-setup.pending'):
                try:os.stat(path,dir_fd=resolver.files[0][1],follow_symlinks=False)
                except FileNotFoundError:pass
                else:raise ValueError('existing hook path cannot be adopted')
            plan=bootstrap.prepare(current,bootstrap.inspect_factory(control,watch),source_sha256=source_hash,hook_absent=True)
            return {'eligible':True,'configuration_changed':False,'hook':str(resolver_path.with_name(name)),
                'source_sha256':source_hash,'expected_modules':plan['expected_modules'],'native_resolver_apply_required':True,'rules_changed':False}
        cache=NativeConfigCache(locks/'config.cache',expected_uid=uid,expected_gid=gid);stack.callback(cache.close)
        if action=='install':
            base=stack.enter_context(SourceAudit([SourceSpec('plain_base',str(root/'dnsalias/plainhook.py'),uid,gid,(0o600,),65536)],ancestor_uids=(0,)))
            if base.hashes['plain_base']!=manifest['files']['dnsalias/plainhook.py']:raise ValueError('owned package base source changed')
            from .plainlibrary import LibraryFile
            library=stack.enter_context(LibraryFile(data,expected_uid=0))
            return install(journal,config,resolver,base,codec,cache,guard,reload,control,watch,library=library)
        hook=stack.enter_context(SourceAudit([SourceSpec('selected_hook',str(resolver_path.with_name(bootstrap.BASENAME+'.py')),unbound.pw_uid,unbound.pw_gid,(0o600,),65536)],ancestor_uids=owners))
        result=(unselect if action=='unselect' else retire)(journal,config,hook,codec,cache,guard,reload,control,watch)
        if action=='retire':
            from .plainlibrary import LibraryFile,retire as library_retire
            with LibraryFile(data,expected_uid=0) as library:result.update(library_retire(library))
        return result


def main():
    import argparse
    parser=argparse.ArgumentParser(description='Owned plain-Unbound first-hook setup. Install/unselect require a subsequent native DNS Resolver Save/Apply. No automatic service or rule changes.')
    parser.add_argument('action',choices=('review','install','inspect','unselect','retire'));args=parser.parse_args()
    import manage
    if current(manage.ROOT,manage.DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(manage.ROOT/'dnsalias/lifecycle.py'),'operator','plainsetup',*sys.argv[1:]])
    try:print(json.dumps(operate(args.action)))
    except Exception as exc:
        print(str(exc)[:500],file=sys.stderr);raise SystemExit(1)


if __name__=='__main__':main()
