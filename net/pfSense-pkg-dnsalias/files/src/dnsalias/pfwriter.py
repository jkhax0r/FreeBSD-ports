"""Explicit normalized-lease/PF component; not an enforcement service.

Caller must first own the namespace, qualify/authenticate the resolver and boot,
arm an independent cleanup watchdog and qualify the shared filter-lock protocol.
This component establishes none of those prerequisites and sends no DNS ACK.
No default paths, processes, table/rule creation, hook changes or automatic retry.

The persistent owner can opt to finish an already admitted, count-bounded
synchronization after its ACK budget. It cannot renew a TTL, send a late ACK,
or recover uncertain kernel writes; all other guards still apply. Admission
after an expired budget changes no ledger or PF state.

One owner thread calls observe() for normalized trusted replies, tick() without
waiting for queries, and periodic off-path audit(). Borrowed resources stay owned
by the caller. Any failure after ledger processing begins is sticky; independent
cleanup is then required because PF may contain only some of the staged changes.
"""
import time
import os
from contextlib import nullcontext

from .checkpoint import elapsed_checked
from .indexedproofs import IndexedProofLedger
from .pfapi import NativePFTables,MAX_BATCH
from .reloadlock import SharedReloadLock,ReloadBusy
from .replygate import clock
from .membershipgate import MembershipGate


class WriterSuspended(RuntimeError):pass
class WriterDeadline(RuntimeError):pass


class LeaseTableWriter:
    MAX_CHANGES=4096

    def __init__(self,ledger,writer,*,reload_lock_path,lock_uid=0,membership_gate=None,allow_late_completion=False,confirmation=None):
        if (not isinstance(ledger,IndexedProofLedger) or ledger.proofs or ledger.leases or ledger.anchors
            or not ledger.policies):raise ValueError('fresh nonempty-policy indexed ledger required')
        if (not isinstance(writer,NativePFTables) or not writer.writable or writer.state!='enrolled'
            or writer.total!=0 or any(writer.known.values())):raise ValueError('fresh enrolled empty native tables required')
        names=tuple('da_'+policy.name for policy in ledger.policies)
        if set(names)!=set(writer.names):raise ValueError('exact separate policy table set required')
        if membership_gate is not None and (type(membership_gate) is not MembershipGate
            or (membership_gate.descriptor['uid'],membership_gate.descriptor['gid'])!=(os.geteuid(),os.getegid())
            or not membership_gate.available()):
            raise ValueError('fresh available shared membership gate required')
        self.membership_gate=membership_gate
        if type(allow_late_completion) is not bool:raise ValueError('explicit late-completion mode required')
        self.allow_late_completion=allow_late_completion;self._synchronizing=False
        self.ledger,self.writer=ledger,writer
        self.lock=SharedReloadLock(reload_lock_path,expected_uid=lock_uid)
        self.state='ready';self.reason=None;self.previous_clock=None;self.updates=0
        self.max_expiry_batches=0
        # Optional native confirmation capability. Normal writers allocate no
        # page and have no publisher. Binding never establishes external source,
        # process, filter-reload or independent-cleanup qualification.
        self.confirmation=confirmation;self._confirming=False
        if confirmation is not None:confirmation.bind(self)

    def _suspend(self,reason):
        self.state='suspended'
        if self.reason is None:self.reason=reason
        if self.confirmation is not None:self.confirmation.close()

    def _time(self):
        mono,utc=clock(time.monotonic()),clock(time.time())
        if self.previous_clock is not None:elapsed_checked(self.previous_clock,(mono,utc),.25)
        self.previous_clock=mono,utc
        return mono,utc

    def _check(self,guard,deadline):
        now,utc=self._time()
        if now>=deadline and not (self.allow_late_completion and self._synchronizing):raise WriterDeadline('membership operation deadline reached')
        if not guard.valid():raise WriterSuspended('native reload lock identity changed')
        if self.membership_gate is not None and not self.membership_gate.valid():raise WriterSuspended('membership gate ended')
        if self.writer.state!='enrolled':raise WriterSuspended('native writer is no longer enrolled')
        return now,utc

    def _sync(self,change,guard,deadline,remaining_changes):
        removed=change['tables_removed'];added=change['tables_added']
        total=sum(map(len,removed.values()))+sum(map(len,added.values()))
        if total>remaining_changes:raise OverflowError('per-operation membership change budget exceeded')
        after=self.writer.total-sum(map(len,removed.values()))+sum(map(len,added.values()))
        if not 0<=after<=self.writer.max_members:raise OverflowError('native total membership capacity exceeded')
        for policy,addresses in removed.items():
            if not addresses<=self.writer.known['da_'+policy]:raise WriterSuspended('removal baseline differs from ledger')
        for policy,addresses in added.items():
            if addresses&self.writer.known['da_'+policy]:raise WriterSuspended('addition baseline differs from ledger')
        operations=0
        for groups,operation in ((removed,self.writer.delete),(added,self.writer.add)):
            for policy,addresses in groups.items():
                values=sorted(addresses)
                for offset in range(0,len(values),MAX_BATCH):
                    self._check(guard,deadline)
                    operation('da_'+policy,set(values[offset:offset+MAX_BATCH]));operations+=1
        # Every caller immediately follows with _drain_expiry() or _check().
        # That fresh check covers the final mutation (and empty deltas); doing
        # another identical check here only repeated metadata/kernel queries.
        return operations,remaining_changes-total

    def _drain_expiry(self,guard,deadline,remaining):
        # One owner admits no new proofs during synchronization. Each catch-up
        # removes at least one existing heap entry, so persistent completion is
        # bounded by the already retained proof count and MAX_CHANGES. A fixed
        # two-pass tail could fail solely because another TTL crossed during
        # the preceding pass. No deadline/TTL is renewed to finish this work.
        limit=len(self.ledger._deadlines.heap) if self.allow_late_completion else 2
        operations=batches=0
        for attempt in range(limit+1):
            now,utc=self._check(guard,deadline);next_deadline=self.ledger._deadlines.next
            if next_deadline is None or next_deadline>now:return operations,remaining,next_deadline,batches
            if attempt==limit:raise WriterDeadline('expiry changed faster than bounded synchronization')
            before=len(self.ledger._deadlines.heap)
            extra,remaining=self._sync(self.ledger.expire_changes(now),guard,deadline,remaining)
            operations+=extra;batches+=1
            if len(self.ledger._deadlines.heap)>=before:raise WriterSuspended('expiry catch-up made no progress')
        raise WriterSuspended('expiry catch-up bound violated')

    def _run(self,event,deadline,*,audit=False,policies=None):
        if self.state!='ready':raise WriterSuspended('membership component is suspended')
        deadline=clock(deadline);started=time.monotonic()
        if self.allow_late_completion and started>=deadline:raise WriterDeadline('request expired before processing')
        if not 0<deadline-started<=(1 if audit else .1):raise ValueError('bounded future operation deadline required')
        started_processing=False
        try:
            with (self.membership_gate if self.membership_gate is not None else nullcontext()),self.lock as guard:
                now,utc=self._check(guard,deadline);started_processing=True;self._synchronizing=True
                if self.confirmation is not None:self.confirmation.prepare_scope(self,event,policies)
                change=(self.ledger.reconfigure_changes(policies,now) if policies is not None else
                        self.ledger.expire_changes(now) if event is None else self.ledger.observe_changes(event,now,utc))
                operations,remaining=self._sync(change,guard,deadline,self.MAX_CHANGES)
                extra,remaining,next_deadline,batches=self._drain_expiry(guard,deadline,remaining);operations+=extra
                if audit:
                    self.writer.audit()
                    extra,remaining,next_deadline,after=self._drain_expiry(guard,deadline,remaining);operations+=extra;batches+=after
                self.max_expiry_batches=max(self.max_expiry_batches,batches)
                self.updates+=1
                result={'memberships_synchronized':True,'kernel_operations':operations,'members':self.writer.total,
                    'next_deadline':next_deadline,'expiry_batches':batches,'dns_reply_authorized':False,'new_rules_created':False}
                if self.confirmation is not None and event is not None:
                    # Publish while both writer locks are still held, after PF
                    # synchronization and expiry catch-up. A returned result
                    # cannot later be replayed as publication authority.
                    self._confirming=True
                    try:self.confirmation.synchronized(self,event,result,deadline)
                    finally:self._confirming=False
                    self._check(guard,deadline)
                return result
        except ReloadBusy:
            if started_processing:self._suspend('reload_became_busy_after_processing')
            raise
        except WriterDeadline:
            if started_processing or not self.allow_late_completion:self._suspend('membership_step_failed:WriterDeadline')
            raise
        except Exception as exc:
            self._suspend('membership_step_failed:'+type(exc).__name__)
            raise
        finally:self._synchronizing=False

    def observe(self,event,*,deadline):return self._run(event,deadline)
    def tick(self,*,deadline):return self._run(None,deadline)
    def audit(self,*,deadline):return self._run(None,deadline,audit=True)

    def reconfigure(self,policies,*,deadline):
        """Owner-loop pattern edit on the already enrolled exact table set.

        Shares the normal expiry, reload lock and sticky failure boundary. No
        rule, hook, source client, table identity or original deadline changes.
        New names require subsequent trusted replies before membership appears.
        """
        from .leases import Policy
        policies=tuple(policies)
        if (any(type(p) is not Policy for p in policies)
            or len(policies)!=len(self.ledger.policies)
            or {p.name for p in policies}!={p.name for p in self.ledger.policies}):
            raise ValueError('pattern edits require the same distinct enrolled policies')
        return self._run(None,deadline,policies=policies)

    def replace_policies(self,policies,*,deadline):
        """Saved alias add/remove/edit, after caller qualifies table ownership."""
        from .leases import Policy
        policies=tuple(policies)
        if (self.state!='ready' or any(type(p) is not Policy for p in policies)
            or not {'da_'+p.name for p in policies}<=set(self.writer.names)):
            raise ValueError('owned enrolled policy tables required')
        started_processing=False
        try:
            with (self.membership_gate if self.membership_gate is not None else nullcontext()),self.lock as guard:
                now,utc=self._check(guard,deadline)
                started_processing=True
                if self.confirmation is not None:self.confirmation.prepare_scope(self,policies=policies)
                change=self.ledger.replace_policy_set(policies,now)
                operations,_=self._sync(change,guard,deadline,self.MAX_CHANGES)
                self._check(guard,deadline)
                return {'memberships_synchronized':True,'kernel_operations':operations,'members':self.writer.total}
        except ReloadBusy:
            if started_processing:self._suspend('reload_became_busy_after_policy_processing')
            raise
        except Exception as exc:
            self._suspend('policy_replacement_failed:'+type(exc).__name__)
            raise

    def retire(self,*,deadline):
        """One-way normal shutdown of a healthy, exclusively owned writer.

        Caller must keep namespace ownership and its independent watchdog.
        Audit the exact enrolled baseline before deleting any memberships, use
        the shared reload lock throughout, then verify empty native tables.
        No rule/table/state deletion or adoption of outside changes. Failure
        permanently suspends this component; only independent qualified cleanup
        may resolve a partial or uncertain outcome. Never retry this method.
        """
        if self.state!='ready':raise WriterSuspended('only a healthy writer can retire')
        deadline=clock(deadline);started=time.monotonic()
        if not 0<deadline-started<=1:raise ValueError('bounded future retirement deadline required')
        if self.confirmation is not None:self.confirmation.close()
        self.state='retiring';operations=0;removed=self.writer.total
        try:
            with (self.membership_gate if self.membership_gate is not None else nullcontext()),self.lock as guard:
                self._check(guard,deadline)
                self.writer.audit()
                self._check(guard,deadline)
                for name in self.writer.names:
                    values=sorted(self.writer.known[name])
                    for offset in range(0,len(values),MAX_BATCH):
                        self._check(guard,deadline)
                        self.writer.delete(name,set(values[offset:offset+MAX_BATCH]));operations+=1
                self._check(guard,deadline);self.writer.audit();self._check(guard,deadline)
                if self.writer.total!=0:raise WriterSuspended('retirement left native memberships')
                self.state='retired';self.reason='caller_retired'
                return {'retired':True,'memberships_removed':removed,'kernel_operations':operations,
                    'tables_verified_empty':True,'rules_changed':False,'states_changed':False,
                    'automatic_retry':False}
        except Exception as exc:
            self._suspend('retirement_failed:'+type(exc).__name__)
            raise

    def close(self):
        # Closing handles alone has never implied that native memberships were
        # cleared. Preserve a completed retirement receipt in subsequent status.
        if self.state!='retired':self._suspend('caller_closed')
        self.lock.close()
        # The optional membership gate is borrowed; its creating owner closes
        # it only after all users have stopped. Closing never implies disarm.

    def retire_external(self,*,deadline):
        """Terminal read-only retirement after an independently completed drain.

        The caller has stopped its reply loop and retains this exact session.
        No old membership is adopted and no mutation is attempted. The original
        writer descriptor is closed permanently after fresh empty verification.
        """
        from pathlib import Path
        from .membershipgate import ExclusiveMembershipGate
        from .registeredcleanup import DrainFile
        from .trialtable import _Receipt as TableReceipt
        if self.state=='retired' or self.membership_gate is None:
            raise WriterSuspended('one registered external retirement required')
        deadline=clock(deadline)
        if not 0<deadline-time.monotonic()<=1:raise ValueError('bounded external retirement deadline required')
        if self.confirmation is not None:self.confirmation.close()
        descriptor=dict(self.membership_gate.descriptor);directory=Path(descriptor['path']).parent
        fence=ExclusiveMembershipGate(descriptor,disarmed=True)
        try:
            with fence,self.lock as guard,DrainFile(directory,expected_uid=descriptor['uid']) as store,TableReceipt(directory,expected_uid=descriptor['uid']) as owner:
                def check():
                    if time.monotonic()>=deadline or not fence.valid() or not guard.valid():
                        raise WriterSuspended('external retirement guard ended')
                check();record=store.read();binding=owner.read()
                if record is None or binding is None:raise ValueError('completed bound drain required')
                value=record['checkpoint'];receipt=binding['checkpoint']
                if (len(self.writer.names)!=1 or value['phase']!='complete' or not value['empty_verified']
                    or value['gate']!=descriptor or value['table']!=self.writer.names[0]
                    or value['table_receipt_sha256']!=binding['file_sha256']
                    or receipt.get('phase')!='acquired' or receipt.get('membership_gate')!=descriptor
                    or receipt.get('registration_receipt_sha256')!=value['installation_sha256']
                    or receipt.get('registration_boot_id')!=value['boot_id']
                    or (directory/store.PENDING).exists() or (directory/store.PENDING).is_symlink()):
                    raise ValueError('exact completed session drain required')
                with NativePFTables('',self.writer.names,max_members=self.writer.max_members) as observed:
                    for unused in range(2):
                        if any(observed.snapshot().values()):raise WriterSuspended('independently drained table is not empty')
                        check()
                if store.read()!=record or owner.read()!=binding:raise ValueError('external drain proof changed')
                check();self.writer.close()
                self.writer.known={name:set() for name in self.writer.names};self.writer._packed_known={name:set() for name in self.writer.names}
                self.writer.total=0;self.state='retired';self.reason='independent_drain_verified'
                return {'retired':True,'external_drain':True,'tables_verified_empty':True,
                    'kernel_operations':0,'rules_changed':False,'states_changed':False,'automatic_retry':False,
                    'drain_receipt_sha256':record['file_sha256']}
        except Exception as exc:
            self._suspend('external_retirement_failed:'+type(exc).__name__);raise
        finally:fence.close()

    def status(self):
        return {'state':self.state,'reason':self.reason,'updates':self.updates,'members':self.writer.total,'max_expiry_batches':self.max_expiry_batches,
            'membership_gate_configured':self.membership_gate is not None,
            'next_deadline':None if self.state=='retired' else self.ledger._deadlines.next,'independent_watchdog_required':True,
            'resolver_authentication_required':True,'automatic_recovery':False,'service_activation':False}
