"""Explicit ownership of one fresh root PF table for the short trial caller.

No rule, alias, DNS, state or boot changes. Uses the already qualified complete
PF reference capture under native guards. A private receipt is written BEFORE
each mutation. An exception after an attempt leaves the receipt and resources
for inspection; this object never retries, adopts an old table, or auto-cleans.
The caller separately owns the directory and must stop all borrowed table
writers and disarm its consumer before requesting removal.
"""
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from contextlib import contextmanager

from .blocktrial import validate as validate_rule,gate_identity
from .policystats import rule_ids
from .checkpointfile import CheckpointFile
from .pfcapture import PFReferenceCapture,PFCaptureError
from .reloadlock import SharedReloadLock,ExclusiveConfigLock
from .sourceaudit import SourceAudit,SourceSpec


class _Receipt(CheckpointFile):
    NAME='table-owner.json';PENDING='table-owner.pending';LOCK='table-owner.lock'
    ENVELOPE_FORMAT='dnsalias-table-owner-envelope-1'
    PAYLOAD_FORMAT='dnsalias-table-owner-1'


def validate_scope(value):
    """A reserved table namespace alone confers no traffic-rule authority."""
    if type(value) is dict and set(value)=={'token','table','anchor'}:
        token=value['token']
        if (type(token) is not str or not re.fullmatch('[a-f0-9]{16}',token)
            or value['table']!='da_mvp_'+token[:12] or value['anchor']!='dnsalias_trial_'+token):
            raise ValueError('exact reserved table namespace required')
        return dict(value)
    return validate_rule(value)


def referenced(name,capture):
    """Exact PF table tokens; prefix collisions cannot authorize a removal."""
    if not re.fullmatch(r'da_[a-z][a-z0-9_]{0,22}',name):raise ValueError('owned policy table required')
    pattern=r'<'+re.escape(name)+r'(?::[^>\n]+)?>'
    return any(re.search(pattern,capture[key]) for key in ('filter_rules','nat_rules'))


class TrialTable:
    def __init__(self,rule,*,directory,gate_path,gate_inode,reload_lock_path,config_lock_path):
        self.spec=validate_scope(rule)
        if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root table owner required')
        self.path=Path(directory);self.gate_path=Path(gate_path);self.gate_inode=tuple(gate_inode)
        if self.gate_path.parent!=self.path or gate_identity(self.gate_path)!=self.gate_inode:
            raise ValueError('exact caller-owned gate in private runtime directory required')
        self.receipt=self.audit=None;self.gate=self.reload=self.config=None
        self.digest=None;self.state='new';self.created=False;self.attempt=None;self.failed=False
        try:
            self.receipt=_Receipt(self.path,expected_uid=0)
            if self.receipt.read() is not None:raise ValueError('existing table receipt requires inspection')
            self.gate=ExclusiveConfigLock(self.gate_path)
            self.reload=SharedReloadLock(reload_lock_path);self.config=ExclusiveConfigLock(config_lock_path)
            self.audit=SourceAudit([SourceSpec('pfctl_binary','/sbin/pfctl',0,0,(0o555,),1024*1024)],ancestor_uids=(0,))
            self._record('prepared')
        except Exception:self.close();raise

    def _record(self,phase):
        value={'format':_Receipt.PAYLOAD_FORMAT,'rule':self.spec,'phase':phase,
               'updated_monotonic':time.monotonic(),'updated_utc':time.time(),
               'automatic_retry':False}
        self.digest=self.receipt.save(value,expected_digest=self.digest);self.state=phase

    def _check(self):
        if gate_identity(self.gate_path)!=self.gate_inode or not all(g.valid() for g in (self.gate,self.reload,self.config)):
            raise ValueError('table owner guards changed')
        self.audit.audit()
        record=self.receipt.read()
        if record is None or record['file_sha256']!=self.digest:raise ValueError('table owner receipt changed')

    def _capture(self):
        # PF can retire an empty unreachable anchor after its final owner exits,
        # even while native reload/config guards are held. Only an observed
        # inventory/reference change permits one new READ-ONLY capture. A fresh
        # object still needs two complete matching rounds under these guards.
        # No PF mutation or uncertain operation is repeated.
        for attempt in range(2):
            self._check();capture=PFReferenceCapture(self.audit,self.reload,self.config)
            try:
                capture.capture();values=capture.arguments()
                return values,capture.result['anchors']
            except PFCaptureError as exc:
                self.capture_error=exc.details
                if attempt or not exc.volatile:raise
                self.reference_recaptures=getattr(self,'reference_recaptures',0)+1

    def _command(self,args,body=None):
        self._check()
        result=subprocess.run(['/sbin/pfctl',*args],input=body,text=True,capture_output=True,
            timeout=1,pass_fds=(self.gate.fd,self.reload.fd,self.config.fd),
            env={'PATH':'/sbin:/bin:/usr/sbin:/usr/bin','LC_ALL':'C','LANG':'C'})
        if result.returncode or len(result.stdout)>65536 or len(result.stderr)>4096:
            raise RuntimeError('native table operation requires inspection')
        self._check();return result.stdout

    @contextmanager
    def _operation(self):
        if self.failed:raise ValueError('prior table operation requires inspection')
        try:
            with self.gate,self.reload,self.config:yield
        except Exception:
            self.failed=True
            raise

    def create(self,*,before_create=None):
        if self.state!='prepared' or self.attempt is not None:raise ValueError('fresh single-use table preparation required')
        if before_create is not None and not callable(before_create):raise ValueError('optional final precondition required')
        with self._operation():
            capture,anchors=self._capture();name=self.spec['table'];anchor=self.spec['anchor']
            occupied=set(re.findall(r'\bridentifier ([0-9]+)\b',capture['filter_rules']+'\n'+capture['nat_rules']))
            if occupied.intersection(rule_ids(self.spec)):raise ValueError('named policy rule identifier collision')
            if name in capture['existing_tables'] or referenced(name,capture):raise ValueError('trial table collision or consumer exists')
            if any(a==anchor or a.startswith(anchor+'/') for a in anchors):raise ValueError('trial anchor collision')
            if before_create is not None and before_create() is not True:raise ValueError('pre-Start configuration changed')
            self._record('create_intent');self.attempt='create'
            self._command(['-t',name,'-T','add','-f','-'],'')
            if name not in self._command(['-s','Tables']).split() or self._command(['-t',name,'-T','show']).strip():
                raise RuntimeError('new empty root table not verified')
            self.created=True;self._record('created')
        return self.status()

    def remove(self,*,writers_stopped,consumer_removed):
        if writers_stopped is not True or consumer_removed is not True:
            raise ValueError('caller must separately fence writers and remove consumer')
        if self.state!='created' or not self.created or self.attempt!='create':
            raise ValueError('owned confirmed table required; inspect uncertain outcomes')
        with self._operation():
            capture,_=self._capture();name=self.spec['table']
            if name not in capture['existing_tables'] or referenced(name,capture):raise ValueError('table missing or still consumed; inspect')
            if self._command(['-t',name,'-T','show']).strip():raise ValueError('table still populated; writer retirement required')
            self._record('remove_intent');self.attempt='remove'
            self._command(['-t',name,'-T','kill'])
            if name in self._command(['-s','Tables']).split():raise RuntimeError('table removal not verified')
            self.created=False;self._record('removed')
        return self.status()

    def status(self):
        return {'state':self.state,'table':self.spec['table'],'table_created':self.created,
                'mutation_attempt':self.attempt,'receipt_sha256':self.digest,
                'inspection_required':self.failed or self.state in ('create_intent','remove_intent'),
                'rules_changed':False,'automatic_retry':False,
                'read_only_reference_recaptures':getattr(self,'reference_recaptures',0),'last_capture_error':getattr(self,'capture_error',None)}

    def close(self):
        # Closing descriptors never deletes a kernel object or a receipt.
        for name in ('audit','config','reload','gate','receipt'):
            value=getattr(self,name,None)
            if value is not None:value.close();setattr(self,name,None)


class RegisteredTable(TrialTable):
    """Inactive registered-table lifecycle, separate from ephemeral MVP tables.

    A completed owned saved definition permits only EMPTY table acquisition.
    Release leaves that empty table for ordinary consumers; removal is a later
    explicit unused-only action. No lease adoption, rule creation, alias write,
    full filter reload, boot registration or automatic recovery. Caller still
    fences all writers and removes its own consumer before release/retirement.
    """
    def __init__(self,rule,*,authority,**kwargs):
        from .aliascoordinator import SavedAliasAuthority
        if type(authority) is not SavedAliasAuthority or type(rule) is not dict or rule.get('table')!=authority.table:
            raise ValueError('exact saved alias authority required')
        self.authority=authority;self.created_by_session=False;self.membership_gate_descriptor=None
        super().__init__(rule,**kwargs)

    def _record(self,phase):
        value={'format':_Receipt.PAYLOAD_FORMAT,'rule':self.spec,'phase':phase,
            'updated_monotonic':time.monotonic(),'updated_utc':time.time(),
            'automatic_retry':False,'registration_receipt_sha256':self.authority.digest,
            'registration_boot_id':self.authority.boot,'membership_gate':self.membership_gate_descriptor}
        self.digest=self.receipt.save(value,expected_digest=self.digest);self.state=phase

    def create(self,*,before_create=None):
        if self.state!='prepared' or self.attempt is not None:raise ValueError('fresh registered acquisition required')
        if before_create is not None and not callable(before_create):raise ValueError('optional final precondition required')
        with self._operation():
            capture,anchors=self._capture();name=self.spec['table'];anchor=self.spec['anchor']
            occupied=set(re.findall(r'\bridentifier ([0-9]+)\b',capture['filter_rules']+'\n'+capture['nat_rules']))
            if occupied.intersection(rule_ids(self.spec)):raise ValueError('registered rule identity collision')
            if any(a==anchor or a.startswith(anchor+'/') for a in anchors):raise ValueError('registered consumer anchor collision')
            self.authority.review(self.reload,self.config)
            present=name in capture['existing_tables']
            if present and self._command(['-t',name,'-T','show']).strip():
                raise ValueError('registered table is populated; never adopt or flush old memberships')
            if before_create is not None and before_create() is not True:raise ValueError('configuration changed before acquisition')
            self._record('acquire_intent');self.attempt='acquire'
            if not present:
                self._command(['-t',name,'-T','add','-f','-'],'');self.created_by_session=True
            if name not in self._command(['-s','Tables']).split() or self._command(['-t',name,'-T','show']).strip():
                raise RuntimeError('registered empty table acquisition not verified')
            self.created=True;self._record('acquired')
        return self.status()

    def remove(self,**kwargs):
        raise ValueError('registered tables require explicit release, then unused-only retirement')

    def bind_membership_gate(self,descriptor):
        """Bind one gate to this acquired table before any writer starts.

        The private table receipt, not a caller's matching filenames, establishes
        which registered table a later exclusive cleanup gate actually fences.
        No PF mutation or policy activation occurs here.
        """
        from .membershipgate import MembershipGate,validate as validate_gate
        descriptor=validate_gate(descriptor)
        if (self.state!='acquired' or self.membership_gate_descriptor is not None
            or Path(descriptor['path']).parent!=self.path
            or (descriptor['uid'],descriptor['gid'])!=(self.authority.uid,self.authority.gid)):
            raise ValueError('one fresh same-directory table gate binding required')
        gate=MembershipGate(descriptor)
        try:
            with self._operation():
                self.authority.review(self.reload,self.config)
                if not gate.available() or self._command(['-t',self.spec['table'],'-T','show']).strip():
                    raise ValueError('bind an available gate while the acquired table is empty')
                self.membership_gate_descriptor=descriptor;self._record('acquired')
        finally:gate.close()
        return self.status()

    def release(self,*,writers_stopped,consumer_removed):
        if writers_stopped is not True or consumer_removed is not True:
            raise ValueError('fenced writers and removed owned consumer required')
        if self.state!='acquired' or not self.created or self.attempt!='acquire':
            raise ValueError('confirmed registered acquisition required')
        with self._operation():
            capture,anchors=self._capture();name=self.spec['table'];anchor=self.spec['anchor']
            self.authority.review(self.reload,self.config)
            if name not in capture['existing_tables']:raise ValueError('registered table vanished; inspect')
            if any(a.startswith(anchor+'/') for a in anchors):raise ValueError('unexpected descendant consumer')
            for key in ('filter_rules','nat_rules'):
                marker='# PF anchor '+anchor+'\n'
                section=capture[key].split(marker,1)[1].split('\n# PF anchor ',1)[0].strip() if marker in capture[key] else ''
                if section:raise ValueError('owned consumer still has rules')
            if self._command(['-t',name,'-T','show']).strip():raise ValueError('retire writer memberships before release')
            self._record('released');self.created=False
        return self.status()

    def retire_unused(self):
        """Delete once only after release and complete saved/runtime no-use proof."""
        if self.state!='released' or self.attempt!='acquire':raise ValueError('released registered table required')
        with self._operation():
            capture,_=self._capture();name=self.spec['table']
            review=self.authority.review(self.reload,self.config)
            if review['saved_external_references'] or referenced(name,capture):
                raise ValueError('ordinary consumers require registered table retention')
            if name not in capture['existing_tables'] or self._command(['-t',name,'-T','show']).strip():
                raise ValueError('registered table missing or populated; inspect')
            self._record('retire_intent');self.attempt='retire'
            self._command(['-t',name,'-T','kill'])
            if name in self._command(['-s','Tables']).split():raise RuntimeError('registered retirement not verified')
            self._record('retired')
        return self.status()

    def status(self):
        return super().status()|{'registered':True,'created_by_session':self.created_by_session,
            'table_released':self.state in ('released','retired'),'table_retained':self.state=='released',
            'table_retired':self.state=='retired',
            'membership_gate_bound':self.membership_gate_descriptor is not None,
            'inspection_required':self.failed or self.state in ('acquire_intent','retire_intent')}
