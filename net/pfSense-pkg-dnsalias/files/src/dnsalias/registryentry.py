"""Owned native parse_config entry for the package's reserved-table adapter.

The native coordinator provisions it on fresh install or explicit stopped
source Apply. Registration is request-local and does not modify core files.
Install/update/remove is journaled and never adopts an existing unowned entry
or replays a partial outcome. Existing catalog resync is read-only.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from .checkpointfile import CheckpointFile
from .lifecycle import guarded
from .nativebootstrap import NATIVE_SOURCES

ROOT=Path('/usr/local/libexec/dnsalias')
DATA=Path('/var/db/dnsalias')
ENTRY=Path('/usr/local/pkg/parse_config/dnsalias.inc')
MODULE='native/registry.php'


class RegistryFile(CheckpointFile):
    NAME='native-registry.json';PENDING='native-registry.pending';LOCK='native-registry.lock'
    ENVELOPE_FORMAT='dnsalias-native-registry-envelope-1';PAYLOAD_FORMAT='dnsalias-native-registry-owner-1'


def _canonical(path):
    path=Path(path)
    if not path.is_absolute() or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,511}',str(path)) or '..' in path.parts:
        raise ValueError('Canonical native registry path required')
    if path.resolve(strict=True)!=path:raise ValueError('Native registry path symlink refused')
    return path


def _directory(path,uid,private=False):
    _canonical(path);info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or stat.S_IMODE(info.st_mode) not in ((0o700,) if private else (0o700,0o755))):
        raise ValueError('Native registry directory ownership changed')
    return info


def _read(path,uid,limit):
    before=path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid!=uid or stat.S_IMODE(before.st_mode)!=0o600
        or before.st_nlink!=1 or not 0<before.st_size<=limit):raise ValueError('Native registry file ownership changed')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        if identity(os.fstat(fd))!=identity(before):raise ValueError('Native registry file replaced')
        raw=os.read(fd,limit+1)
        if len(raw)!=before.st_size or identity(os.fstat(fd))!=identity(before) or identity(path.lstat())!=identity(before):raise ValueError('Native registry file changed during read')
        return raw
    finally:os.close(fd)


def plan(root=ROOT,data=DATA,entry=ENTRY):
    root,data,entry=Path(root),Path(data),Path(entry);uid=os.geteuid()
    for path in (root,data):_directory(path,uid,True)
    if root==ROOT:
        if data!=DATA or entry!=ENTRY or uid!=0:raise ValueError('Exact native registry paths required')
    elif entry!=root.parent/'parse_config/dnsalias.inc':raise ValueError('Private registry entry must remain beside private source')
    # manage.install/upgrade use a private0700 root and ordinary0755 child
    # directories. Their contents still require exact0600 manifest ownership.
    _directory(entry.parent,uid);_directory(root/'native',uid)
    owner=json.loads(_read(data/'OWNER.json',uid,4096))
    if owner!={'owner':'dnsalias-observation-v1','root':str(root)}:raise ValueError('Native registry data authority changed')
    manifest=json.loads(_read(root/'MANIFEST.json',uid,1048576))
    module=_read(root/MODULE,uid,65536);digest=hashlib.sha256(module).hexdigest()
    if manifest.get('owner')!='dnsalias-observation-v1' or manifest.get('format')!=1 or manifest.get('files',{}).get(MODULE)!=digest:
        raise ValueError('Native registry module differs from owned manifest')
    functions=[name.decode() for name in re.findall(rb'^function (dnsalias_registry_[a-z_]+)\(',module,re.M)]
    if not 1<=len(functions)<=16 or len(set(functions))!=len(functions) or len(re.findall(rb'^function ',module,re.M))!=len(functions):
        raise ValueError('Bounded unique registry function namespace required')
    configuration={'format':'dnsalias-native-registry-entry-1','root':str(root),'data':str(data),'uid':uid,
        'module':MODULE,'module_sha256':digest,'native_sources':NATIVE_SOURCES,'functions':functions}
    encoded=base64.b64encode(json.dumps(configuration,sort_keys=True,separators=(',',':')).encode()).decode()
    if not module.startswith(b'<?php\n') or module.count(b'<?php')!=1 or b'?>' in module:raise ValueError('Self-contained registry module source required')
    source=PHP.replace('CONFIGURATION_BASE64',encoded).replace('MODULE_SOURCE',module.removeprefix(b'<?php\n').decode('utf-8')).encode()
    return {'format':RegistryFile.PAYLOAD_FORMAT,'root':str(root),'data':str(data),'entry':str(entry),
            'entry_sha256':hashlib.sha256(source).hexdigest(),'module_sha256':digest,'source':source}


def _receipt(journal,root,data,entry):
    old=journal.read()
    if old is None:return None
    value=old['checkpoint']
    if (value.get('phase')!='complete' or value.get('root')!=str(root) or value.get('data')!=str(data)
        or value.get('entry')!=str(entry) or set(value)!={'format','root','data','entry','entry_sha256','module_sha256','phase'}):
        raise ValueError('Native registry operation requires inspection')
    if hashlib.sha256(_read(entry,os.geteuid(),65536)).hexdigest()!=value['entry_sha256']:
        raise ValueError('Native registry entry changed; no adoption or overwrite')
    return old


@guarded()
def inspect(root=ROOT,data=DATA,entry=ENTRY):
    root,data,entry=Path(root),Path(data),Path(entry)
    proposed=plan(root,data,entry)
    if (data/RegistryFile.PENDING).exists() or os.path.lexists(entry.with_name('dnsalias.inc.pending')):raise ValueError('Pending native registry operation requires inspection')
    with RegistryFile(data,expected_uid=os.geteuid()) as journal:
        old=_receipt(journal,root,data,entry)
        if old is None:
            if os.path.lexists(entry):raise ValueError('Unowned native registry entry; no adoption')
            return {'installed':False,'proposed':{k:v for k,v in proposed.items() if k!='source'}}
        return {'installed':True,'matches_source':all(old['checkpoint'][k]==proposed[k] for k in ('entry_sha256','module_sha256')),'receipt':old}


def enrollment_sources(root=ROOT,data=DATA,entry=None):
    """Return startup-only source pins; no calls occur in DNS callbacks."""
    from .sourceaudit import SourceSpec
    root,data=Path(root),Path(data);entry=Path(entry) if entry is not None else ENTRY if root==ROOT else root.parent/'parse_config/dnsalias.inc'
    if not os.path.lexists(data/RegistryFile.NAME) and not os.path.lexists(data/RegistryFile.PENDING):
        if os.path.lexists(entry):raise ValueError('Unowned native registry entry; no enrollment')
        return [],{}
    value=inspect(root,data,entry)
    if not value['installed'] or not value['matches_source']:raise ValueError('Matching owned native registry sources required for enrollment')
    # The receipt is validated at startup. It is an installer authority, not
    # runtime code; watching its busy data-directory parent would cause audits
    # on every ordinary status publication. Runtime watches cover the immutable
    # entry/module and the exact native API code they depend upon instead.
    fields=(('native_registry_entry',entry,value['receipt']['checkpoint']['entry_sha256']),
            ('native_registry_module',root/MODULE,value['receipt']['checkpoint']['module_sha256']))
    specs=[SourceSpec(name,str(path),os.geteuid(),os.getegid(),(0o600,),65536) for name,path,unused in fields]
    hashes={name:digest for name,unused,digest in fields}
    for i,(path,digest) in enumerate(NATIVE_SOURCES.items()):
        name='native_registry_core_'+str(i);specs.append(SourceSpec(name,path,0,0,(0o644,),1000000));hashes[name]=digest
    return specs,hashes


@guarded(mode='write',control=True)
def provision(root=ROOT,data=DATA,entry=ENTRY):
    """Provision only the shared extension directory, never adopt an entry."""
    root,data,entry=Path(root),Path(data),Path(entry);uid=os.geteuid()
    if root==ROOT:
        if data!=DATA or entry!=ENTRY or uid!=0:raise ValueError('Exact native registry paths required')
    elif entry!=root.parent/'parse_config/dnsalias.inc':raise ValueError('Private registry entry must remain beside private source')
    parent=entry.parent;_directory(parent.parent,uid)
    created=False
    if not os.path.lexists(parent):
        # Root-owned shared parent, with no users other than root able to
        # replace its path. Leave this generic directory on later removal.
        parent.mkdir(mode=0o755);created=True
        fd=os.open(parent.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    _directory(parent,uid)
    result=inspect(root,data,entry)
    return {'directory_created':created,'entry_present':result['installed']}


@guarded(mode='write',control=True)
def install(root=ROOT,data=DATA,entry=ENTRY):
    root,data,entry=Path(root),Path(data),Path(entry);proposed=plan(root,data,entry);pending=entry.with_name('dnsalias.inc.pending')
    if os.path.lexists(pending) or (data/RegistryFile.PENDING).exists():raise ValueError('Pending native registry operation requires inspection')
    with RegistryFile(data,expected_uid=os.geteuid()) as journal:
        old=_receipt(journal,root,data,entry)
        if old is None and os.path.lexists(entry):raise ValueError('Unowned native registry entry; no adoption')
        if old is not None and all(old['checkpoint'][k]==proposed[k] for k in ('entry_sha256','module_sha256')):
            return {'installed':True,'unchanged':True}
        value={k:v for k,v in proposed.items() if k!='source'};value.update(phase='prepared',prior_entry_sha256=old['checkpoint']['entry_sha256'] if old else None)
        digest=journal.save(value,expected_digest=old['file_sha256'] if old else None)
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            os.fchmod(fd,0o600);view=memoryview(proposed['source'])
            while view:
                n=os.write(fd,view)
                if n<=0:raise OSError('Short native registry publication')
                view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        if old is None:
            if os.path.lexists(entry):raise ValueError('Native registry entry appeared during publication')
        elif hashlib.sha256(_read(entry,os.geteuid(),65536)).hexdigest()!=old['checkpoint']['entry_sha256']:
            raise ValueError('Native registry entry changed during publication')
        os.replace(pending,entry)
        directory=os.open(entry.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
        if hashlib.sha256(_read(entry,os.geteuid(),65536)).hexdigest()!=proposed['entry_sha256']:raise ValueError('Native registry readback differs; inspect outcome')
        value.pop('prior_entry_sha256');value['phase']='complete';journal.save(value,expected_digest=digest)
        return {'installed':True,'unchanged':False,'entry_sha256':proposed['entry_sha256']}


@guarded(mode='write',control=True)
def remove(root=ROOT,data=DATA,entry=ENTRY):
    root,data,entry=Path(root),Path(data),Path(entry);plan(root,data,entry)
    if os.path.lexists(entry.with_name('dnsalias.inc.pending')) or (data/RegistryFile.PENDING).exists():raise ValueError('Pending native registry operation requires inspection')
    with RegistryFile(data,expected_uid=os.geteuid()) as journal:
        old=_receipt(journal,root,data,entry)
        if old is None:
            if os.path.lexists(entry):raise ValueError('Unowned native registry entry; no removal')
            return {'removed':False}
        # Caller must separately qualify stopped owners and unused tables.
        value=old['checkpoint']|{'phase':'removing'};journal.save(value,expected_digest=old['file_sha256'])
        entry.unlink()
        directory=os.open(entry.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(directory)
        finally:os.close(directory)
        os.unlink(journal.NAME,dir_fd=journal.fd);os.fsync(journal.fd)
        return {'removed':True,'shared_extension_directory_retained':True}


PHP=r'''<?php
/* DNS Alias owned native parse_config entry. Generated; no core-file edits.
 * Registry functions are copied inline from the manifest-verified module.
 * No managed-source include or lifetime wait occurs during native parsing.
 * Each request keeps its loaded code and native configuration snapshot.
 */
(static function(): void {
    $GLOBALS['dnsalias_registry_status']=['state'=>'checking'];
    try {
        $cfg=json_decode(base64_decode('CONFIGURATION_BASE64',true),true,16,JSON_THROW_ON_ERROR);
        $identity=[$cfg['root'],$cfg['data'],$cfg['module_sha256'],__FILE__];
        $repeat=($GLOBALS['dnsalias_registry_entry_identity']??null)===$identity;
        foreach($cfg['functions'] as $function){
            if($repeat){
                if(!function_exists($function)||(new ReflectionFunction($function))->getFileName()!==__FILE__)
                    throw new RuntimeException('Native registry function ownership changed');
            }elseif(function_exists($function))throw new RuntimeException('Native registry function namespace collision');
        }
        if(!$repeat){
MODULE_SOURCE
            $GLOBALS['dnsalias_registry_entry_identity']=$identity;
        }
        if(!function_exists('config_get_path'))throw new RuntimeException('Native configuration API unavailable');
        if(config_get_path('installedpackages/dnsalias/native_alias_mode','legacy')==='legacy'){
            $GLOBALS['dnsalias_registry_status']=['state'=>'inactive','mode'=>'legacy'];return;
        }
        foreach($cfg['native_sources'] as $path=>$digest){
            $s=@lstat($path);if(!$s||($s['mode']&0170000)!==0100000||$s['uid']!==0||($s['mode']&0022)!==0||$s['size']>1000000||hash_file('sha256',$path)!==$digest)
                throw new RuntimeException('Native alias API version changed');
        }
        $GLOBALS['dnsalias_registry_status']=dnsalias_registry_bootstrap()+[
            'format'=>'dnsalias-native-registry-status-1','root'=>$cfg['root'],'data'=>$cfg['data'],
            'entry_module_sha256'=>$cfg['module_sha256']];
    }catch(Throwable $error){$GLOBALS['dnsalias_registry_status']=['state'=>'unavailable','reason'=>$error->getMessage()];}
})();
'''
