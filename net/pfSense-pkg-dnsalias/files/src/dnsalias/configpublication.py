"""Inactive receipt-bound publication of unused saved aliases only.

No default target, active-alias removal, cache invalidation, filter reload, DNS hook,
rule or PF mutation. Caller must own both native guards and complete fresh PF
filter/NAT/table captures, taken under those guards; strings alone do not prove
capture completeness. Caller owns revision/backup policy and recovery lifecycle.
This consumes one fresh config SourceAudit, even on failure, but borrows the
guards, codec and private receipt. Error outcomes always require inspection.
Same-owner/root writers bypassing the qualified lock protocol are out of scope.
"""
import copy
from dataclasses import asdict
import hashlib
import os
import re
import time

from .aliasinstall import AliasInstallFile
from .aliasrefs import plan_saved_install,plan_saved_removal
from .aliasremove import AliasRemovalFile,bound_installation
from .checkpoint import identity
from .configcodec import NativeConfigCodec
from .hookfile import _read,_pending,_parents
from .pfcapture import PFReferenceCapture
from .reloadlock import ExclusiveConfigLock,SharedReloadLock
from .sourceaudit import SourceAudit


class ConfigPublicationError(ValueError):
    def __init__(self,*,replacement_attempted,stage):
        super().__init__('configuration publication incomplete during '+stage+'; inspect current file and receipt before any further action')
        self.replacement_attempted=replacement_attempted
        self.stage=stage


def publish_install(audit,config_guard,reload_guard,codec,journal,*,boot_id,filter_rules,nat_rules,existing_tables):
    """Publish only the unused-alias addition bound to a prepared receipt.

    Hold the shared filter guard before the exclusive config guard. Rebuild the
    candidate from the inspected current bytes; match its parsed/file hashes,
    exact definitions and prior container shape to the immutable receipt. A
    successful result records publication with cache completion still false.
    Caller must finish cache handling/readback under the same native guards and
    independently qualify recovery before exposing any enforcement controls.
    """
    return _publish(audit,config_guard,reload_guard,codec,journal,boot_id=boot_id,
        filter_rules=filter_rules,nat_rules=nat_rules,existing_tables=existing_tables,installation=None)


def publish_unused_removal(audit,config_guard,reload_guard,codec,journal,installation,*,boot_id,filter_rules,nat_rules,existing_tables):
    """Remove exact unused aliases bound to their completed original install.

    Complete fresh PF captures must show no references and no corresponding root
    tables. This deliberately does not retire an active writer, remove tables,
    reload filters or remove rules. Caller must independently exclude future
    writers and own recovery. Unrelated current configuration is preserved.
    """
    if type(installation) is not AliasInstallFile:
        if isinstance(audit,SourceAudit):audit.close()
        raise ValueError('owned installation journal required')
    return _publish(audit,config_guard,reload_guard,codec,journal,boot_id=boot_id,
        filter_rules=filter_rules,nat_rules=nat_rules,existing_tables=existing_tables,installation=installation)


def publish_captured_install(audit,config_guard,reload_guard,codec,journal,references,*,boot_id):
    """Use the complete captured PF view and recheck it through publication."""
    return _captured(audit,config_guard,reload_guard,codec,journal,references,boot_id=boot_id,installation=None)


def publish_captured_unused_removal(audit,config_guard,reload_guard,codec,journal,installation,references,*,boot_id):
    """Bind narrow unused-alias removal to a complete fresh PF view."""
    if type(installation) is not AliasInstallFile:
        if isinstance(audit,SourceAudit):audit.close()
        raise ValueError('owned installation journal required')
    return _captured(audit,config_guard,reload_guard,codec,journal,references,boot_id=boot_id,installation=installation)


def _captured(audit,config_guard,reload_guard,codec,journal,references,*,boot_id,installation):
    try:
        if (type(references) is not PFReferenceCapture or references.reload is not reload_guard
            or references.config is not config_guard):
            raise ValueError('complete PF capture must bind these exact native guards')
        arguments=references.arguments()
    except Exception:
        if isinstance(audit,SourceAudit):audit.close()
        raise ConfigPublicationError(replacement_attempted=False,stage='reference_capture') from None
    return _publish(audit,config_guard,reload_guard,codec,journal,boot_id=boot_id,
        **arguments,installation=installation,reference_capture=references)


def _publish(audit,config_guard,reload_guard,codec,journal,*,boot_id,filter_rules,nat_rules,existing_tables,installation,reference_capture=None):
    if not isinstance(audit,SourceAudit):raise ValueError('fresh native config source audit required')
    pending_fd=None;parent=None;pending_name=None;pending_identity=None;renamed=False;attempted=False
    deadline=time.monotonic()+2;stage='validation'
    def within():
        if time.monotonic()>=deadline:raise ValueError('configuration publication deadline')
    def guarded():
        within()
        if (type(config_guard) is not ExclusiveConfigLock or type(reload_guard) is not SharedReloadLock
            or not config_guard.valid() or not reload_guard.valid()
            or config_guard.identity==reload_guard.identity):
            raise ValueError('distinct held qualified native configuration and filter guards required')
        if reference_capture is not None:
            current=reference_capture.arguments()
            if current!={'filter_rules':filter_rules,'nat_rules':nat_rules,'existing_tables':existing_tables}:
                raise ValueError('PF reference snapshot changed during publication')
    try:
        identity(boot_id);guarded()
        journal_type=AliasInstallFile if installation is None else AliasRemovalFile
        if not isinstance(codec,NativeConfigCodec) or type(journal) is not journal_type:
            raise ValueError('qualified codec and owned installation receipt required')
        if audit.state!='qualified' or len(audit.files)!=1:raise ValueError('one fresh inspected native config required')
        entry=audit.files[0];spec,source_parent,name,source_fd,metadata=entry
        if spec.name!='firewall_config' or name!='config.xml' or spec.modes!=(0o600,) or journal.uid!=spec.uid or os.geteuid() not in (0,spec.uid):
            raise ValueError('private native config ownership required')
        receipt=journal.read()
        if receipt is None:raise ValueError('durable prepared installation receipt required')
        value=receipt['checkpoint'];plan=value['plan']
        def check_installation():
            if installation is not None:
                if installation.uid!=journal.uid:raise ValueError('installation/removal ownership differs')
                bound_installation(value,installation.read())
        check_installation()
        if value['status']['phase']!='prepared' or plan['boot_id']!=boot_id:
            raise ValueError('only same-boot prepared unused-alias installation is eligible')
        if plan['config']!=(asdict(spec)|{'modes':list(spec.modes)}):raise ValueError('receipt config specification differs')
        stage='table_namespace'
        if (type(existing_tables) not in (list,tuple) or len(existing_tables)>10000
            or any(type(n) is not str or not re.fullmatch('[A-Za-z0-9_]{1,128}',n) for n in existing_tables)
            or len({n.lower() for n in existing_tables})!=len(existing_tables)):
            raise ValueError('complete bounded native root table inventory required')
        if {n.lower() for n in existing_tables}.intersection(plan['definitions']):
            raise ValueError('existing PF table namespace cannot be adopted')
        stage='current_configuration';audit.audit();original=_read(audit,entry,deadline)
        if hashlib.sha256(original).hexdigest()!=plan['before_file_sha256']:raise ValueError('current config differs from prepared receipt')
        current=codec.decode(original)['configuration'];guarded()
        stage='candidate_validation'
        common=dict(seed_name=plan['seed_name'],definitions=plan['definitions'],configuration=current,
            filter_rules=filter_rules,nat_rules=nat_rules)
        if installation is None:
            candidate=plan_saved_install(**common)
            compared=('before_tree_sha256','after_tree_sha256','definition_sha256','prior_alias_container','prior_alias_list')
        else:
            candidate=plan_saved_removal(**common,prior_alias_container=plan['prior_alias_container'],
                prior_alias_list=plan['prior_alias_list'])
            compared=('before_tree_sha256','after_tree_sha256','definition_sha256')
        for key in compared:
            if candidate[key]!=plan[key]:raise ValueError('fresh alias candidate differs from receipt')
        target=codec.encode(candidate['configuration'])['xml'];guarded()
        if len(target)>spec.max_bytes or hashlib.sha256(target).hexdigest()!=plan['after_file_sha256']:
            raise ValueError('native candidate bytes differ from receipt')
        # Keep our own parent pin for cleanup if the consumed SourceAudit fails.
        stage='file_stage';parent=os.dup(source_parent);pending_name=name+'.dnsalias.pending'
        pending_fd=os.open(pending_name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        info=os.fstat(pending_fd);pending_identity=info.st_dev,info.st_ino
        os.fchown(pending_fd,spec.uid,spec.gid);os.fchmod(pending_fd,0o600)
        _pending(pending_fd,parent,pending_name,spec,0o600,pending_identity)
        view=memoryview(target)
        while view:
            within();count=os.write(pending_fd,view)
            if count<=0:raise OSError('short staged config write')
            view=view[count:]
        os.fsync(pending_fd);within()
        _pending(pending_fd,parent,pending_name,spec,0o600,pending_identity)
        def staged_content():
            chunks=[];offset=0
            if os.fstat(pending_fd).st_size!=len(target):raise ValueError('staged config size changed')
            while offset<len(target):
                within();chunk=os.pread(pending_fd,min(65536,len(target)-offset),offset)
                if not chunk:raise ValueError('short staged config read')
                chunks.append(chunk);offset+=len(chunk)
            return b''.join(chunks)
        if staged_content()!=target:raise ValueError('staged config bytes changed')
        audit.audit();guarded()
        if journal.read()!=receipt:raise ValueError('prepared receipt changed before publication')
        check_installation()
        _pending(pending_fd,parent,pending_name,spec,0o600,pending_identity)
        stage='file_replace';attempted=True
        os.replace(pending_name,name,src_dir_fd=parent,dst_dir_fd=parent);renamed=True
        stage='file_verification';os.fsync(parent);within();guarded();_parents(audit)
        _pending(pending_fd,parent,name,spec,0o600,pending_identity)
        if staged_content()!=target:raise ValueError('published config bytes changed')
        _parents(audit);guarded();_pending(pending_fd,parent,name,spec,0o600,pending_identity)
        check_installation();updated=copy.deepcopy(value)
        updated['status'].update(phase='published',updated_monotonic=time.monotonic(),updated_utc=time.time(),
            observed_file_sha256=plan['after_file_sha256'],directory_synced=True,cache_invalidated=False)
        stage='receipt_record';receipt_digest=journal.save(updated,expected_digest=receipt['file_sha256'])
        guarded()
        return {'changed':True,'disk_state':'published','configuration_sha256':plan['after_file_sha256'],
            'receipt_sha256':receipt_digest,'cache_invalidated':False,'publication_complete':False,
            'traffic_rules_changed':False,'filter_reloaded':False,
            ('added_names' if installation is None else 'removed_names'):list(plan['definitions'])}
    except Exception:
        raise ConfigPublicationError(replacement_attempted=attempted,stage=stage) from None
    finally:
        try:
            if pending_fd is not None:os.close(pending_fd)
            if pending_identity is not None and not renamed:
                try:remaining=os.stat(pending_name,dir_fd=parent,follow_symlinks=False)
                except OSError:remaining=None
                if remaining is not None and pending_identity==(remaining.st_dev,remaining.st_ino):os.unlink(pending_name,dir_fd=parent)
        finally:
            if parent is not None:os.close(parent)
            audit.close()
