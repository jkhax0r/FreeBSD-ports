"""Inactive guarded reply/native-writer composition; no service activation.

The caller supplies already-owned empty tables or an explicit persistent-owner
handoff of the same healthy writer, controlled generation, native
process watch, independent source/runtime audit and cleanup watchdog. Periodic
audit gaps and native lifecycle integration still require qualification before
production enforcement. No sockets, ACK sending, hook loading, rules, process
creation or automatic recovery are performed here.
"""
import re
import time
import json

from .deployment import DeploymentGuard
from .ipc import Credentials
from .pfwriter import LeaseTableWriter,WriterDeadline
from .replygate import ReplyGate,clock
from .replynormalize import ReplyProfile,UnqualifiedReply,normalize
from .confirmationkey import confirmation_key, key_with_loss_counter, resolved_cache_key
from .reloadlock import ReloadBusy


class ReplyWriterSession:
    def __init__(self,*,profile,guard,writer,processing_budget=.04,lease_owner=None):
        if (not isinstance(profile,ReplyProfile) or not isinstance(guard,DeploymentGuard)
            or profile.identifier!=guard.expected.identifier
            or profile.excluded_addresses!=guard.expected.excluded_addresses
            or guard.process_watch is None or guard.generation is None
            or guard.check()!='qualified'):
            raise ValueError('matching qualified watched profile and controlled generation required')
        if lease_owner is None:
            owner=getattr(writer,'_persistent_reply_owner',None)
            if (not isinstance(writer,LeaseTableWriter) or writer.state!='ready' or writer.writer.total or writer.updates
                or owner is not None):
                raise ValueError('fresh empty owned table writer required')
        else:
            from .replyowner import PersistentReplyOwner
            if type(lease_owner) is not PersistentReplyOwner or not lease_owner._permits(writer,guard):
                raise ValueError('explicit in-process persistent writer handoff required')
        if type(processing_budget) not in (int,float) or not 0<processing_budget<=.05:
            raise ValueError('bounded reply processing budget required')
        self.profile,self.guard,self.writer=profile,guard,writer
        self.lease_owner=lease_owner
        self.tolerate_late=getattr(writer,'allow_late_completion',False) is True
        self.budget=processing_budget;self.gate=ReplyGate(max_delivery_age=processing_budget)
        self.state='ready';self.reason=None
        self.table_audit_pending=False
        self.startup_open=True;self.startup_count=self.startup_bytes=0
        self.startup_deadline=guard.generation.received_monotonic+5
        self.startup_gate=ReplyGate()

    def replay_startup(self,event,credentials,*,deadline):
        """Seed only during unreferenced startup; never produce a DNS ACK.

        Caller must keep traffic rules disarmed throughout this phase, and
        supply the bounded queue handed off by ReplyStartup.take(guard).
        Original observation clocks/TTLs are retained. This does not claim the
        already released warming reply waited for PF or authorize any traffic.
        The first authenticated normal process() call permanently ends replay.
        """
        if not self.startup_open or time.monotonic()>=self.startup_deadline:
            raise ValueError('startup replay closed; no late seeding or recovery')
        producer=self.guard.producer
        if (not isinstance(credentials,Credentials)
            or any(type(n) is not int for n in (credentials.pid,credentials.uid,credentials.euid))
            or (credentials.pid,credentials.uid,credentials.euid)!=(producer.pid,producer.uid,producer.uid)):
            raise ValueError('authenticated startup producer required')
        if not self._healthy():return {'ack':None,'reason':self.reason,'startup_only':True,'traffic_authorized':False}
        try:
            size=len(json.dumps(event,separators=(',',':'),allow_nan=False).encode())
            if (type(event) is not dict or self.startup_count>=256 or size>60000 or self.startup_bytes+size>512*1024
                or event.get('profile_id')!=self.profile.identifier or type(event.get('transport_dropped_before')) is not int
                or event['transport_dropped_before']!=0 or self.guard.check_generation(event)!='qualified'):
                raise ValueError('startup queue identity or bounds changed')
            self.startup_count+=1;self.startup_bytes+=size
            self.startup_gate.accept(event,received_monotonic=time.monotonic(),received_utc=time.time())
            normalized=normalize(event,profile=self.profile,resolver_epoch=self.guard.generation.generation)
        except UnqualifiedReply:
            return {'ack':None,'reason':'unsupported_startup_reply','startup_only':True,'traffic_authorized':False}
        except (ValueError,TypeError,KeyError,RecursionError):
            self._suspend('startup_queue_unqualified')
            return {'ack':None,'reason':self.reason,'startup_only':True,'traffic_authorized':False}
        try:
            synchronized=self.writer.observe(normalized,deadline=deadline)
            if not self._healthy():raise ValueError('startup qualification ended')
        except Exception as exc:
            self._suspend('startup_writer_failed:'+type(exc).__name__)
            return {'ack':None,'reason':self.reason,'startup_only':True,'traffic_authorized':False}
        return {'ack':None,'reason':'startup_memberships_seeded','startup_only':True,
            'traffic_authorized':False,'synchronization':synchronized}

    def finish_startup(self):
        """Caller must separately verify drained queue/tables before arming rules."""
        self.startup_open=False

    def _suspend(self,reason):
        confirmation=self._confirmation()
        if confirmation is not None:confirmation.invalidate()
        if self.reason is None:self.reason=reason
        self.state='suspended';self.guard.suspend(reason)

    def _confirmation(self):
        # A retired receiver can still hold the same writer object. It must
        # neither publish nor revoke the new owner's confirmations.
        claimed=getattr(self.writer,'_persistent_reply_owner',None)
        if claimed is not None and (claimed() is not self.lease_owner or self.lease_owner is None
            or self.lease_owner.session is not self):return None
        return self.writer.confirmation

    def _healthy(self):
        claimed=getattr(self.writer,'_persistent_reply_owner',None)
        if claimed is not None and (claimed() is not self.lease_owner or self.lease_owner is None
            or self.lease_owner.session is not self):
            # An older raw receiver may still hold this writer/guard. Revoke
            # only that session's authority; its borrowed guard might also
            # have been supplied to the currently active owner session.
            self.state='suspended';self.reason='writer_session_retired';return False
        reason=self.guard.check()
        if reason!='qualified':self._suspend(reason)
        elif self.writer.state!='ready':self._suspend('writer_unavailable')
        return self.state=='ready'

    def process(self,event,credentials):
        """Produce only a candidate ACK after bounded synchronized processing.

        Credentials must come from the native receiver. A foreign producer gets
        no reply and cannot poison the owned session. Candidate ACKs mean table
        synchronization, never a firewall allow decision or proven delivery.
        Caller still checks its endpoint/deadline immediately before sending.
        """
        producer=self.guard.producer
        if (not isinstance(credentials,Credentials)
            or any(type(n) is not int for n in (credentials.pid,credentials.uid,credentials.euid))
            or (credentials.pid,credentials.uid,credentials.euid)!=(producer.pid,producer.uid,producer.uid)):
            return {'ack':None,'reason':'untrusted_producer'}
        if type(event) is not dict or type(event.get('request_id')) is not str or not re.fullmatch('[a-f0-9]{32}',event['request_id']):
            return {'ack':None,'reason':'invalid_request_identity'}
        self.startup_open=False
        token=event['request_id']
        owner = self.lease_owner
        isolate_misses = owner is not None and owner.allow_reported_reply_loss
        def result(status,reason,**details):
            # These outcomes happened before table mutation. A known missed
            # observation cannot invalidate a previously committed answer.
            if status!='applied' and not (isolate_misses and reason in ('request_budget_expired','unsupported_reply')):
                confirmation=self._confirmation()
                if confirmation is not None:confirmation.invalidate()
            return {'ack':{'request_id':token,'status':status},'reason':reason,
                    'traffic_authorized':False,**details}
        if not self._healthy():return result('helper_error',self.reason)
        if event.get('profile_id')!=self.profile.identifier:
            self._suspend('reply_profile_changed');return result('helper_error',self.reason)
        if isolate_misses:
            try:
                if time.monotonic()>=clock(event['monotonic'])+self.budget:
                    return result('helper_error','request_budget_expired')
            except (ValueError,KeyError):
                self._suspend('reply_clock_or_shape_changed');return result('helper_error',self.reason)
        reason=self.guard.check_generation(event)
        if reason!='qualified':
            self._suspend(reason);return result('helper_error',self.reason)
        dropped = event.get('transport_dropped_before')
        if (type(dropped) is not int or not 0 <= dropped <= 2**63 - 1
                or (dropped and not isolate_misses)):
            self._suspend('reply_transport_gap');return result('helper_error',self.reason)
        try:
            started=clock(event['monotonic']);deadline=started+self.budget
            now,utc=time.monotonic(),time.time()
            # Queueing consumes the original request budget. It never receives
            # a new full budget on arrival at the helper.
            if now>=deadline:return result('helper_error','request_budget_expired')
            self.gate.accept(event,received_monotonic=now,received_utc=utc)
            if dropped:
                # A missed observation cannot justify a new lease. Later
                # qualified replies and already-justified leases are independent.
                owner._record_reply_loss(dropped, utc)
            normalized=normalize(event,profile=self.profile,resolver_epoch=self.guard.generation.generation)
        except UnqualifiedReply:
            return result('ignored','unsupported_reply')
        except (ValueError,KeyError,TypeError):
            self._suspend('reply_clock_or_shape_changed');return result('helper_error',self.reason)
        if self.table_audit_pending:
            # A known native reload prevented the scheduled table check. Keep
            # answering promptly, but do not claim/apply a mapping until the
            # sole owner completes that check under the native filter lock.
            return result('helper_error','reload_busy')
        # Only an authenticated, current and normalized reply reaches this
        # optional publisher. The digest binds the original complete answer;
        # publication still occurs inside the writer's existing PF locks.
        confirmation=self._confirmation()
        if confirmation is not None:
            # The owner may supply the same source/hash-qualified native key
            # already used in the resolver. Normalization and all writer/PF
            # qualification remain independent; this only selects the digest
            # implementation, with the original Python path as its default.
            try:
                key = confirmation_key if confirmation.answer_key is None else confirmation.answer_key
                digest = (resolved_cache_key(event, key) if event.get('callback')=='resolved'
                          else key_with_loss_counter(event, key))
                if digest is not None and (type(digest) is not bytes or len(digest)!=32):
                    raise ValueError('invalid answer digest')
            except Exception:
                self._suspend('confirmation_key_unqualified');return result('helper_error',self.reason)
            if digest is not None:
                with confirmation.for_reply(digest,self._healthy):
                    return self._synchronize(normalized,deadline,result)
        return self._synchronize(normalized,deadline,result)

    def _synchronize(self,normalized,deadline,result):
        try:
            synchronized=self.writer.observe(normalized,deadline=deadline)
        except ReloadBusy:
            if self.writer.state!='ready':self._suspend('reload_conflict_after_processing')
            return result('helper_error','reload_busy')
        except WriterDeadline:
            if self.tolerate_late and self.writer.state=='ready':return result('helper_error','request_budget_expired')
            self._suspend('writer_step_failed:WriterDeadline');return result('helper_error',self.reason)
        except Exception as exc:
            self._suspend('writer_step_failed:'+type(exc).__name__)
            return result('helper_error',self.reason)
        # Process lifetime/audit freshness may change during the kernel call.
        # Never issue a success acknowledgement for that uncertain interval.
        if not self._healthy():return result('helper_error',self.reason)
        if time.monotonic()>=deadline:
            if self.tolerate_late:
                return result('applied','memberships_synchronized_after_ack_deadline',synchronization=synchronized,send_before=deadline)
            self._suspend('request_deadline_after_processing');return result('helper_error',self.reason)
        return result('applied','memberships_synchronized',synchronization=synchronized,send_before=deadline)

    def tick(self,*,deadline):
        """Caller schedules idle expiry; a stopped session requires cleanup."""
        if not self._healthy():return False
        try:self.writer.tick(deadline=deadline)
        except ReloadBusy:return False
        except Exception as exc:self._suspend('writer_tick_failed:'+type(exc).__name__);return False
        return self._healthy()

    def status(self):
        return {'state':self.state,'reason':self.reason,'writer':self.writer.status(),
                'independent_cleanup_required':self.state!='ready','production_enforcement_qualified':False,
                'processing_budget_seconds':self.budget,'automatic_recovery':False}

    def audit(self,*,deadline):
        """Owner-loop consistency check; this can delay queued DNS work.

        Caller supplies a bounded deadline and schedules outside individual
        reply processing. No parallel access to the borrowed writer is allowed.
        A known-unexecuted busy acquisition propagates ReloadBusy so the owner
        can defer within its original audit deadline. Any processing failure
        remains sticky and requires independent cleanup.
        """
        if not self._healthy():return False
        try:self.writer.audit(deadline=deadline)
        except ReloadBusy:
            if self.writer.state!='ready':
                self._suspend('reload_conflict_after_processing');return False
            raise
        except Exception as exc:self._suspend('writer_audit_failed:'+type(exc).__name__);return False
        return self._healthy()

    def reconfigure(self,policies,*,deadline):
        """Occasional owner-loop name edit under the same deployment guard."""
        if not self._healthy():return False
        try:self.writer.reconfigure(policies,deadline=deadline)
        except ReloadBusy:return False
        except Exception as exc:self._suspend('writer_policy_edit_failed:'+type(exc).__name__);return False
        return self._healthy()
