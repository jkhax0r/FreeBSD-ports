"""Inactive atomic byte replacement of one explicitly inspected Python hook.

No default path, resolver reload, process signal, configuration or PF operation.
Caller must serialize native package/config writers, persist the ownership
record before application, and arm independent router-local rollback first.
The file-inode lock coordinates competing operations on that inspected inode;
it is NOT a global lock across native regenerations or replacement inodes.
Same-owner/root hostile races are outside this ownership model.

Each operation consumes its fresh SourceAudit, including failure/no-op. Do not
pass an audit used by a running worker. Atomic rename protects file contents,
not loaded-code state or crash durability after an unsuccessful directory fsync.
After any exception inspect the actual current file before deciding to retry.
"""
import ast
import hashlib
import os
import re
import stat
import time

from .hookplan import LIMIT,state as overlay_state,restore as original_bytes
from .reloadlock import fcntl
from .sourceaudit import SourceAudit,SourceChanged


class HookFileChanged(ValueError):pass
class HookFileBusy(RuntimeError):pass


def _digest(raw):return hashlib.sha256(raw).hexdigest()


def _manifest(value):
    fields={'format','original_size','original_sha256','installed_sha256','observer_sha256','dispatcher_sha256'}
    if type(value) is not dict or set(value)!=fields or value['format']!='dnsalias-hook-overlay-1':
        raise HookFileChanged('complete explicit overlay ownership record required')
    if type(value['original_size']) is not int or not 0<value['original_size']<=512*1024:
        raise HookFileChanged('invalid original policy length')
    for name in fields-{'format','original_size'}:
        if type(value[name]) is not str or not re.fullmatch('[a-f0-9]{64}',value[name]):
            raise HookFileChanged('invalid ownership digest')
    return dict(value)


def _read(audit,entry,deadline):
    spec,parent,name,fd,metadata=entry
    chunks=[];offset=0
    while offset<metadata[6]:
        if time.monotonic()>=deadline:raise HookFileChanged('hook file operation deadline')
        chunk=os.pread(fd,min(65536,metadata[6]-offset),offset)
        if not chunk:raise HookFileChanged('short inspected hook read')
        chunks.append(chunk);offset+=len(chunk)
    raw=b''.join(chunks)
    audit.audit()
    if _digest(raw)!=audit.hashes[spec.name]:raise HookFileChanged('inspected hook content changed')
    return raw


def _pending(fd,parent,name,spec,mode,identity=None):
    own=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
    for item in (own,named):
        if (not stat.S_ISREG(item.st_mode) or item.st_nlink!=1 or item.st_uid!=spec.uid
            or item.st_gid!=spec.gid or stat.S_IMODE(item.st_mode)!=mode):
            raise HookFileChanged('pending hook ownership changed')
    found=own.st_dev,own.st_ino
    if found!=(named.st_dev,named.st_ino) or identity not in (None,found):
        raise HookFileChanged('pending hook replaced')
    return found


def _parents(audit):
    # The selected file changes intentionally, so the whole source audit cannot
    # pass after rename. Its still-pinned parent chain must remain identical.
    for parent,name,fd,wanted in audit.directories.values():
        named=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat('/',follow_symlinks=False)
        if audit._directory_metadata(os.fstat(fd))!=wanted or audit._directory_metadata(named)!=wanted:
            raise HookFileChanged('hook ancestor changed during replacement')


def exchange(audit,manifest,*,overlay=None,publication=None):
    """Apply the exact overlay, or restore its original prefix when omitted.

    Only the SourceAudit entry named selected_hook can change. Preserve its
    owner/group/mode. Existing pending files and changed hooks are never adopted
    or removed. Returns disk evidence only; a caller must qualify any reload.
    """
    if not isinstance(audit,SourceAudit):raise ValueError('fresh native source audit required')
    pending_fd=None;pending_identity=None;parent=None;held_parent=None;pending_name=None;renamed=False
    try:
        owned=_manifest(manifest)
        if fcntl is None or audit.state!='qualified':raise HookFileChanged('qualified native file APIs and source audit required')
        entries=[row for row in audit.files if row[0].name=='selected_hook']
        if len(entries)!=1:raise HookFileChanged('one explicitly inspected selected hook required')
        entry=entries[0];spec,parent,name,fd,metadata=entry
        if (len(name)>128 or not name.endswith('.py') or spec.max_bytes>LIMIT
            or os.geteuid() not in (0,spec.uid)):
            raise HookFileChanged('bounded owned Python hook required')
        deadline=time.monotonic()+1
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError as exc:raise HookFileBusy('inspected hook inode is busy') from exc
        audit.audit();current=_read(audit,entry,deadline)
        before=overlay_state(current,owned)
        if before not in ('original_restored','owned_overlay'):
            raise HookFileChanged('hook changed; leave native or foreign content intact')
        if overlay is None:
            target=original_bytes(current,owned);wanted=owned['original_sha256'];after='original_restored'
        else:
            if type(overlay) is not bytes or not 0<len(overlay)<=LIMIT or _digest(overlay)!=owned['installed_sha256']:
                raise HookFileChanged('exact owned overlay bytes required')
            target=overlay;wanted=owned['installed_sha256'];after='owned_overlay'
            original=original_bytes(target,owned)
            if original!=original_bytes(current,owned):raise HookFileChanged('overlay does not preserve inspected original')
        ast.parse(target)
        if current==target:
            return {'changed':False,'disk_state':after,'sha256':wanted,'loaded_state':'unverified'}
        # A failed SourceAudit closes its descriptors. Keep a separate directory
        # pin so failure cleanup can remove only our own staged inode there.
        held_parent=os.dup(parent);parent=held_parent
        pending_name=name+'.dnsalias.pending'
        pending_fd=os.open(pending_name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        created=os.fstat(pending_fd);pending_identity=created.st_dev,created.st_ino
        os.fchown(pending_fd,spec.uid,spec.gid);os.fchmod(pending_fd,metadata[4])
        _pending(pending_fd,parent,pending_name,spec,metadata[4],pending_identity)
        view=memoryview(target)
        while view:
            if time.monotonic()>=deadline:raise HookFileChanged('hook file operation deadline')
            count=os.write(pending_fd,view)
            if count<=0:raise OSError('short pending hook write')
            view=view[count:]
        os.fsync(pending_fd)
        _pending(pending_fd,parent,pending_name,spec,metadata[4],pending_identity)
        audit.audit()
        if time.monotonic()>=deadline:raise HookFileChanged('hook file operation deadline')
        os.replace(pending_name,name,src_dir_fd=parent,dst_dir_fd=parent);renamed=True
        # An exception after rename leaves the new file visible. The caller
        # must inspect it rather than assuming application did not happen.
        os.fsync(parent)
        _parents(audit)
        _pending(pending_fd,parent,name,spec,metadata[4],pending_identity)
        before_read=os.fstat(pending_fd)
        if before_read.st_size!=len(target):raise HookFileChanged('installed hook size changed')
        digest=hashlib.sha256();offset=0
        while offset<len(target):
            if time.monotonic()>=deadline:raise HookFileChanged('hook file operation deadline')
            chunk=os.pread(pending_fd,min(65536,len(target)-offset),offset)
            if not chunk:raise HookFileChanged('short installed hook read')
            digest.update(chunk);offset+=len(chunk)
        after_read=os.fstat(pending_fd)
        if (digest.hexdigest()!=wanted or (before_read.st_size,before_read.st_mtime_ns,before_read.st_ctime_ns)
            !=(after_read.st_size,after_read.st_mtime_ns,after_read.st_ctime_ns)):
            raise HookFileChanged('installed hook content changed')
        _parents(audit);_pending(pending_fd,parent,name,spec,metadata[4],pending_identity)
        # Cooperating owners may transfer their inode receipt only here: the
        # old inspected inode was exchanged and the new fd/name/bytes verified.
        # A callback failure leaves an inspectable, unadopted outcome.
        if publication is not None:publication(pending_identity)
        return {'changed':True,'disk_state':after,'sha256':wanted,'prior_sha256':_digest(current),
            'loaded_state':'unverified','owner':spec.uid,'group':spec.gid,'mode':oct(metadata[4])}
    finally:
        try:
            if pending_fd is not None:os.close(pending_fd)
            if pending_identity is not None and not renamed:
                try:remaining=os.stat(pending_name,dir_fd=parent,follow_symlinks=False)
                except OSError:remaining=None
                if remaining is not None and pending_identity==(remaining.st_dev,remaining.st_ino):
                    os.unlink(pending_name,dir_fd=parent)
        finally:
            if held_parent is not None:os.close(held_parent)
            audit.close()
