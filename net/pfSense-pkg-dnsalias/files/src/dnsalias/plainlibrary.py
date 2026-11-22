"""One native Python dependency inside a plain Unbound chroot.

Native pfSense mounts /usr/local/lib for Python, but binascii also needs the
base-system libz. Copy the installed library once, with a separate ownership
receipt. Never overwrite/adopt an existing file, follow a link, or repair an
interrupted operation. An exact existing root-owned library may be borrowed;
removal leaves borrowed files alone. No mounts, packages or resolver restart.
"""
from contextlib import ExitStack
import os
from pathlib import Path
import pwd
import stat
import sys
import time

from .checkpointfile import CheckpointFile
from .hookfile import _read,_parents,_pending
from .sourceaudit import SourceAudit,SourceSpec

SOURCE='/lib/libz.so.6'
LIMIT=1024*1024


class LibraryFile(CheckpointFile):
    NAME='plain-library.json';PENDING='plain-library.pending';LOCK='plain-library.lock'
    ENVELOPE_FORMAT='dnsalias-plain-library-envelope-1';PAYLOAD_FORMAT='dnsalias-plain-library-1'


def _root(journal):
    if (type(journal) is not LibraryFile or journal.uid!=0 or os.geteuid()!=0
        or not sys.platform.startswith('freebsd')):raise ValueError('native root library ownership required')
    if os.path.lexists(journal.path/journal.PENDING):raise ValueError('pending plain library operation requires inspection')


def _spec(path):
    path=Path(path)
    if path.name!='libz.so.6' or path.parent.name!='lib' or path.parent.parent.name!='unbound':
        raise ValueError('explicit resolver chroot library path required')
    return SourceSpec('plain_library',str(path),0,0,(0o444,),LIMIT)


def _sources(stack,destination=None):
    specs=[SourceSpec('native_library',SOURCE,0,0,(0o444,),LIMIT)]
    if destination is not None:specs.append(_spec(destination))
    return stack.enter_context(SourceAudit(specs,ancestor_uids=tuple(dict.fromkeys((0,pwd.getpwnam('unbound').pw_uid)))))


def _record(journal):
    _root(journal);previous=journal.read()
    if previous is None:return None
    v=previous['checkpoint']
    fields={'format','phase','destination','sha256','owned','directory_created','directory_identity','file_identity'}
    if (type(v) is not dict or set(v)!=fields or v['format']!=journal.PAYLOAD_FORMAT
        or v['phase'] not in ('prepared','directory_ready','creating','installed','removing','retired')
        or type(v['owned']) is not bool or type(v['directory_created']) is not bool
        or type(v['sha256']) is not str or len(v['sha256'])!=64 or any(c not in '0123456789abcdef' for c in v['sha256'])):
        raise ValueError('plain library receipt changed')
    _spec(v['destination'])
    for name in ('directory_identity','file_identity'):
        if v[name] is not None and (type(v[name]) is not list or len(v[name])!=2 or any(type(n) is not int or not -(1<<63)<=n<(1<<64) for n in v[name])):
            raise ValueError('plain library identity changed')
    if v['phase'] in ('installed','removing','retired') and any(v[k] is None for k in ('directory_identity','file_identity')):
        raise ValueError('plain library identity missing')
    return previous


def _verify(journal,value,stack,*,require_native=True):
    audit=_sources(stack,value['destination']);entry=audit.files[1]
    if (require_native and audit.hashes['native_library']!=value['sha256'] or audit.hashes['plain_library']!=value['sha256']
        or list(entry[4][:2])!=value['file_identity']
        or list(audit.directories[str(Path(value['destination']).parent)][3][:2])!=value['directory_identity']):
        raise ValueError('plain library changed; inspect before starting or removing')
    return audit,entry


def ready(data,*,removing=False):
    data=Path(data)
    if os.path.lexists(data/LibraryFile.PENDING):raise ValueError('pending plain library operation requires inspection')
    if not os.path.lexists(data/LibraryFile.NAME):return
    with LibraryFile(data,expected_uid=0) as journal,ExitStack() as stack:
        v=_record(journal)['checkpoint']
        if v['phase']=='retired':return
        if removing or v['phase']!='installed':raise ValueError('retire the owned plain library; inspect incomplete operations')
        _verify(journal,v,stack)


def install(journal,resolver):
    """Called under the first-hook config/filter guards, before selecting Python."""
    _root(journal)
    if type(resolver) is not SourceAudit or resolver.state!='qualified' or len(resolver.files)!=1:
        raise ValueError('fresh resolver source required')
    entry=resolver.files[0];parent=entry[1]
    if entry[0].name!='resolver_config' or entry[2]!='unbound.conf':raise ValueError('resolver configuration identity required')
    destination=Path(entry[0].path).parent/'lib/libz.so.6';_spec(destination)
    previous=_record(journal)
    if previous is not None and previous['checkpoint']['phase']!='retired':raise ValueError('existing library operation requires inspection')
    with ExitStack() as stack:
        source=_sources(stack);raw=_read(source,source.files[0],time.monotonic()+1)
        if not raw.startswith(b'\x7fELF'):raise ValueError('native ELF library required')
        try:directory=os.stat('lib',dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:directory=None
        if directory is not None and (not stat.S_ISDIR(directory.st_mode) or (directory.st_uid,directory.st_gid)!=(0,0)
            or stat.S_IMODE(directory.st_mode)!=0o755):raise ValueError('existing chroot library directory refused')
        borrowed=None
        if directory is not None:
            fd=os.open('lib',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
            try:os.stat('libz.so.6',dir_fd=fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:
                borrowed=_sources(stack,destination)
                if borrowed.hashes['plain_library']!=source.hashes['native_library']:raise ValueError('existing library differs; no replacement')
        v={'format':journal.PAYLOAD_FORMAT,'phase':'prepared','destination':str(destination),
            'sha256':source.hashes['native_library'],'owned':borrowed is None,'directory_created':directory is None,
            'directory_identity':None,'file_identity':None}
        digest=journal.save(v,expected_digest=previous['file_sha256'] if previous else None)
        def save(phase):
            nonlocal digest
            v['phase']=phase;digest=journal.save(v,expected_digest=digest)
        resolver.audit();source.audit()
        if directory is None:
            os.mkdir('lib',0o755,dir_fd=parent)
            fd=os.open('lib',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);stack.callback(os.close,fd)
            os.fchown(fd,0,0);os.fchmod(fd,0o755);os.fsync(parent)
        d=os.fstat(fd);named=os.stat('lib',dir_fd=parent,follow_symlinks=False)
        if (d.st_dev,d.st_ino)!=(named.st_dev,named.st_ino):raise ValueError('library directory replaced')
        v['directory_identity']=[d.st_dev,d.st_ino];save('directory_ready')
        if borrowed is not None:
            borrowed.audit();v['file_identity']=list(borrowed.files[1][4][:2])
        else:
            save('creating');source.audit();resolver.audit()
            out=os.open('libz.so.6',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444,dir_fd=fd)
            try:
                os.fchown(out,0,0);os.fchmod(out,0o444)
                view=memoryview(raw)
                while view:
                    n=os.write(out,view)
                    if n<=0:raise OSError('short native library copy')
                    view=view[n:]
                os.fsync(out);os.fsync(fd)
                v['file_identity']=list(_pending(out,fd,'libz.so.6',_spec(destination),0o444))
            finally:os.close(out)
        _verify(journal,v,stack);resolver.audit();save('installed')
    return {'library_ready':True,'copied':v['owned'],'destination':v['destination'],'sha256':v['sha256']}


def retire(journal):
    """Caller first verifies native unselection and retires the owned base."""
    previous=_record(journal)
    if previous is None:return {'library_retired':False}
    v=previous['checkpoint']
    if v['phase']!='installed':raise ValueError('installed plain library receipt required')
    with ExitStack() as stack:
        audit,entry=_verify(journal,v,stack,require_native=False)
        v['phase']='removing';digest=journal.save(v,expected_digest=previous['file_sha256'])
        if v['owned']:
            audit.audit();_parents(audit);os.unlink(entry[2],dir_fd=entry[1]);os.fsync(entry[1])
        directory_removed=False
        if v['directory_created']:
            _parents(audit)
            if not os.listdir(entry[1]):
                directory=audit.directories[str(Path(v['destination']).parent)]
                os.rmdir(directory[1],dir_fd=directory[0]);os.fsync(directory[0]);directory_removed=True
        v['phase']='retired';journal.save(v,expected_digest=digest)
    return {'library_retired':True,'owned_library_removed':v['owned'],'borrowed_library_preserved':not v['owned'],'directory_removed':directory_removed}
