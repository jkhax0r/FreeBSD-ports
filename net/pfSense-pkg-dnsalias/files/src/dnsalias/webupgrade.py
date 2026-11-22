"""Explicit single-view update without replacing any running DNS source.

Use a complete verified artifact with exactly one changed presentation file.
Other package management must be serialized by the operator, as for full source
upgrades. One PHP file is replaced atomically; its callers remain unchanged.
Requests may finish with the old view. This does not promise browser/FPM cache
invalidation or semantic compatibility of arbitrary PHP supplied by an operator.
An incomplete transaction is inspected before explicit completion, never retried.
Native package installations must use their normal package update: this writer
cannot update the installer's source identity and GUI receipts together.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

from .checkpointfile import CheckpointFile
from .lifecycle import current,guarded

ASSETS=frozenset('web/'+n+'.php' for n in ('style','client','console','clientview','inspectview','destination','evidence'))
LIMIT=262144


class WebUpdateFile(CheckpointFile):
    NAME='web-update.json';PENDING='web-update.pending';LOCK='web-update.lock'
    ENVELOPE_FORMAT='dnsalias-web-update-envelope-1';PAYLOAD_FORMAT='dnsalias-web-update-1'


class _Operation(CheckpointFile):
    LOCK='web-update.operation.lock'


def _hash(raw):return hashlib.sha256(raw).hexdigest()


def _read(path,limit=LIMIT):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);named=path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o600 or not 0<info.st_size<=limit
            or (info.st_dev,info.st_ino)!=(named.st_dev,named.st_ino)):
            raise ValueError('owned bounded source file required')
        raw=b''
        while len(raw)<=limit:
            block=os.read(fd,min(65536,limit+1-len(raw)))
            if not block:break
            raw+=block
        after=os.fstat(fd);named=path.lstat()
        fields=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns','st_uid','st_gid','st_mode','st_nlink')
        if len(raw)!=info.st_size or any(getattr(info,k)!=getattr(after,k) or getattr(after,k)!=getattr(named,k) for k in fields):
            raise ValueError('source changed while reading')
        return raw,info
    finally:os.close(fd)


def _directory(path):
    info=path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid()
        or stat.S_IMODE(info.st_mode)&0o022):raise ValueError('owned nonwritable source directory required')
    return [info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode)]


def _b64(raw):return base64.b64encode(raw).decode('ascii')


def _owner(root,data):
    import manage
    manage.safe_directory(root);manage.safe_directory(data)
    _directory(root);_directory(data)
    if json.loads(_read(data/'OWNER.json',4096)[0])!={'owner':manage.MARKER,'root':str(root)}:
        raise ValueError('package ownership marker changed')


def _source_only(data):
    # The native bootstrap pins the entire artifact and manifest, including
    # presentation files. Never publish a different identity behind its back.
    # Even incomplete, foreign or dangling metadata must be inspected, not
    # interpreted as permission to bypass the native installation lifecycle.
    for name in ('dnsalias-package','dnsalias-package-gui'):
        try:data.with_name(name).lstat()
        except FileNotFoundError:continue
        raise ValueError('native package metadata is present; use the normal package update')


def _decode(value):
    if not isinstance(value,str) or len(value)>4*((LIMIT+2)//3):raise ValueError('bounded recorded source required')
    raw=base64.b64decode(value,validate=True)
    if len(raw)>LIMIT:raise ValueError('recorded source size exceeded')
    return raw


def _record(store,root):
    if (store.path/store.PENDING).exists():raise ValueError('pending web checkpoint requires inspection')
    value=store.read()
    if value is None:return None
    r=value['checkpoint']
    if (r.get('root')!=str(root) or r.get('member') not in ASSETS
        or r.get('phase') not in ('prepared','asset_replaced','complete','cancelled')
        or not isinstance(r.get('token'),str) or len(r['token'])!=32
        or any(c not in '0123456789abcdef' for c in r['token'])):
        raise ValueError('web update record changed')
    before=json.loads(_decode(r['before_manifest']));after=json.loads(_decode(r['after_manifest']))
    old,new=before['files'],after['files'];member=r['member']
    if (set(old)!=set(new) or member not in old or before['version']!=after['version']
        or any(old[n]!=new[n] for n in old if n!=member)
        or _hash(_decode(r['before_asset']))!=old[member] or _hash(_decode(r['after_asset']))!=new[member]):
        raise ValueError('record is not a single-view update')
    return value


def ready(root,data):
    """Full management retains incomplete web-update evidence before mutation."""
    root,data=map(Path,(root,data))
    if not any((data/n).exists() for n in (WebUpdateFile.NAME,WebUpdateFile.PENDING)):return
    with WebUpdateFile(data,expected_uid=os.geteuid()) as store:
        value=_record(store,root)
        if value is not None and value['checkpoint']['phase'] not in ('complete','cancelled'):
            raise ValueError('incomplete web update; inspect before package management')


def _state(root,r):
    if _directory(root)!=r['root_identity'] or _directory(root/'web')!=r['web_identity']:
        raise ValueError('source directories changed')
    for parent in (root,root/'web'):
        if any(p.name.startswith('.dnsalias-web-') for p in parent.iterdir()):
            raise ValueError('web staging file requires inspection')
    old=json.loads(_decode(r['before_manifest']));new=json.loads(_decode(r['after_manifest']))
    expected=set(old['files'])|{'MANIFEST.json'}
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
    directories={Path(n).parent.as_posix() for n in old['files'] if '/' in n}
    found={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_dir()}
    if actual!=expected or found!=directories or any(p.is_symlink() for p in root.rglob('*')):raise ValueError('source tree changed')
    for name,wanted in old['files'].items():
        if name!=r['member'] and _hash(_read(root/name,2*1024*1024)[0])!=wanted:
            raise ValueError('non-view source changed')
    asset=_read(root/r['member'])[0];manifest=_read(root/'MANIFEST.json')[0]
    a='before' if asset==_decode(r['before_asset']) else 'after' if asset==_decode(r['after_asset']) else 'foreign'
    m='before' if manifest==_decode(r['before_manifest']) else 'after' if manifest==_decode(r['after_manifest']) else 'foreign'
    return {('before','before'):'not_applied',('after','before'):'asset_applied',('after','after'):'complete'}.get((a,m),'conflict')


def _publish(path,expected,body,token):
    """Atomic one-file replacement; clean only our known staging inode."""
    old,info=_read(path)
    if old!=expected:raise ValueError('source changed before publication')
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    pending='.dnsalias-web-'+token;fd=None;identity=None
    try:
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        os.fchown(fd,info.st_uid,info.st_gid);os.fchmod(fd,0o600)
        st=os.fstat(fd);identity=(st.st_dev,st.st_ino)
        view=memoryview(body)
        while view:
            written=os.write(fd,view)
            if written<=0:raise OSError('short web update write')
            view=view[written:]
        os.fsync(fd)
        if _read(path)[0]!=expected:raise ValueError('source changed during staging')
        os.replace(pending,path.name,src_dir_fd=parent,dst_dir_fd=parent);os.fsync(parent)
        if _read(path)[0]!=body:raise ValueError('web update readback differs')
    finally:
        if fd is not None:os.close(fd)
        try:st=os.stat(pending,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:st=None
        if st is not None and (st.st_dev,st.st_ino)==identity:os.unlink(pending,dir_fd=parent)
        os.close(parent)


@guarded(control=True)
def apply(payload,root,data,webpage):
    import manage
    root,data=map(manage.safe_directory,(root,data))
    # Refuse foreign installations before even creating our operation lock.
    _owner(root,data);_source_only(data);ready(root,data);manage.verify(root,data);manage.verify_ui(root,data,webpage)
    with _Operation(data,expected_uid=os.geteuid()) as operation,operation._locked(),WebUpdateFile(data,expected_uid=os.geteuid()) as store:
        _source_only(data);ready(root,data);old=manage.verify(root,data);manage.verify_ui(root,data,webpage)
        files,proposed=manage.unpack(payload)
        if (not isinstance(old.get('version'),str) or not old['version']
            or set(files)!=set(old['files']) or proposed.get('version')!=old.get('version')):
            raise ValueError('web update cannot change core version or file inventory')
        changed=[name for name,body in files.items() if _hash(body)!=old['files'][name]]
        if not changed:return {'updated':False,'reason':'identical source'}
        if len(changed)!=1 or changed[0] not in ASSETS or not 0<len(files[changed[0]])<=LIMIT:
            raise ValueError('exactly one presentation file may change; no core, action or entrypoint update')
        member=changed[0];before_manifest=_read(root/'MANIFEST.json')[0];before_asset=_read(root/member)[0]
        proposed.update(owner=manage.MARKER,artifact_sha256=manage.digest(payload),installed_utc=old['installed_utc'],web_updated_utc=time.time())
        after_manifest=(json.dumps(proposed,sort_keys=True,indent=2)+'\n').encode()
        if len(after_manifest)>LIMIT:raise ValueError('candidate manifest size exceeded')
        r={'format':WebUpdateFile.PAYLOAD_FORMAT,'root':str(root),'member':member,'token':uuid.uuid4().hex,'phase':'prepared',
            'root_identity':_directory(root),'web_identity':_directory(root/'web'),
            'before_manifest':_b64(before_manifest),'after_manifest':_b64(after_manifest),
            'before_asset':_b64(before_asset),'after_asset':_b64(files[member])}
        previous=store.read();receipt=store.save(r,expected_digest=previous['file_sha256'] if previous else None)
        if _state(root,r)!='not_applied':raise ValueError('web update start differs')
        _publish(root/member,before_asset,files[member],r['token']);r['phase']='asset_replaced'
        receipt=store.save(r,expected_digest=receipt)
        if _state(root,r)!='asset_applied':raise ValueError('web update intermediate differs')
        _publish(root/'MANIFEST.json',before_manifest,after_manifest,r['token'])
        manage.verify(root,data);manage.verify_ui(root,data,webpage)
        r['phase']='complete';store.save(r,expected_digest=receipt)
        return {'updated':True,'member':member,'core_sources_replaced':False,'services_restarted':False,'artifact_sha256':manage.digest(payload)}


def inspect(root,data):
    root,data=map(Path,(root,data))
    _owner(root,data)
    with WebUpdateFile(data,expected_uid=os.geteuid()) as store:
        value=_record(store,root)
        if value is None:return {'record':None}
        r=value['checkpoint']
        return {'phase':r['phase'],'member':r['member'],'disk_state':_state(root,r),'source_mutated':False}


@guarded(control=True)
def finish(root,data,webpage):
    """Explicitly reconcile exact recorded bytes; no foreign source adoption."""
    import manage
    root,data=map(Path,(root,data))
    _owner(root,data);_source_only(data);manage.verify_ui(root,data,webpage)
    with _Operation(data,expected_uid=os.geteuid()) as operation,operation._locked(),WebUpdateFile(data,expected_uid=os.geteuid()) as store:
        _source_only(data);value=_record(store,root)
        if value is None:raise ValueError('web update record required')
        r=value['checkpoint'];state=_state(root,r)
        if state=='not_applied':r['phase']='cancelled'
        elif state=='asset_applied':
            _publish(root/'MANIFEST.json',_decode(r['before_manifest']),_decode(r['after_manifest']),r['token']);r['phase']='complete'
        elif state=='complete':r['phase']='complete'
        else:raise ValueError('unrecorded web source; preserve for inspection')
        manage.verify(root,data);manage.verify_ui(root,data,webpage)
        store.save(r,expected_digest=value['file_sha256'])
        return {'reconciled':True,'phase':r['phase'],'services_restarted':False}


def main():
    import manage
    p=argparse.ArgumentParser();p.add_argument('action',choices=('apply','inspect','finish'));p.add_argument('artifact',nargs='?');a=p.parse_args()
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root web updater required')
    if current(manage.ROOT,manage.DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(manage.ROOT/'dnsalias/lifecycle.py'),'operator','webupgrade',*sys.argv[1:]])
    if a.action=='apply':result=apply(Path(a.artifact).read_bytes(),manage.ROOT,manage.DATA,manage.WEBPAGE)
    elif a.action=='finish':result=finish(manage.ROOT,manage.DATA,manage.WEBPAGE)
    else:result=inspect(manage.ROOT,manage.DATA)
    print(json.dumps(result))


if __name__=='__main__':main()
