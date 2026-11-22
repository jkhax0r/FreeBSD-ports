"""Keep one healthy owned lease writer across separately qualified producers.

Inactive until the native service controller is integrated. This is an
in-process ownership handoff, not PF-table adoption or producer authentication.
The caller still owns controlled loads, native credentials, fresh deployment
audits, receive/ACK sockets and an independent cleanup watchdog. No hooks,
services, processes, configuration or rules are created here.
"""
import weakref
import time

from .deployment import DeploymentGuard
from .pfwriter import LeaseTableWriter,WriterSuspended
from .replynormalize import ReplyProfile
from .replywriter import ReplyWriterSession
from .reloadlock import ReloadBusy
from .replygate import clock


class PersistentReplyOwner:
    EXPIRY_RETRY_SECONDS=.05

    def __init__(self,writer,*,allow_reported_reply_loss=False):
        if type(allow_reported_reply_loss) is not bool:
            raise ValueError('explicit reply loss policy required')
        if (not isinstance(writer,LeaseTableWriter) or writer.state!='ready'
            or writer.writer.total or writer.updates or writer.ledger.proofs):
            raise ValueError('fresh empty owned writer required; never adopt existing memberships')
        prior=getattr(writer,'_persistent_reply_owner',None)
        if prior is not None:raise ValueError('writer already has a persistent owner; never adopt an abandoned claim')
        self.writer=writer;self.session=None;self.boot=None;self.last_generation=None;self._binding_guard=None
        self.allow_reported_reply_loss = allow_reported_reply_loss
        self.generation_drops = 0
        self.reported_drops = 0
        self.last_loss_utc = None
        self.expiry_busy_since=None;self.expiry_retry_at=None;self.expiry_deferrals=0;self.expiry_deferred_update=None
        writer._persistent_reply_owner=weakref.ref(self)

    def _permits(self,writer,guard):
        return (writer is self.writer and writer.state=='ready' and self.session is None
            and self._binding_guard is guard and guard is not None)

    def bind(self,*,profile,guard,deadline,processing_budget=.04):
        if self.session is not None or self._binding_guard is not None:raise ValueError('detach the previous producer before binding')
        if (not isinstance(profile,ReplyProfile) or not isinstance(guard,DeploymentGuard)
            or profile.identifier!=guard.expected.identifier or profile.excluded_addresses!=guard.expected.excluded_addresses
            or guard.process_watch is None or guard.generation is None or guard.check()!='qualified'):
            raise ValueError('fresh independently qualified watched producer and controlled generation required')
        if self.boot is not None and guard.producer.boot_id!=self.boot:raise ValueError('cannot carry leases across a different boot')
        if guard.generation.generation==self.last_generation:raise ValueError('retired generation cannot be rebound')
        if type(processing_budget) not in (int,float) or not 0<processing_budget<=.05:raise ValueError('bounded processing budget required')
        # The same writer/ledger/native namespace remains ours. Recheck its
        # exact shadow before allowing another session to use retained leases.
        # Failed/partial/foreign state remains sticky in LeaseTableWriter.
        self.writer.audit(deadline=deadline)
        self._binding_guard=guard
        try:
            session=ReplyWriterSession(profile=profile,guard=guard,writer=self.writer,
                processing_budget=processing_budget,lease_owner=self)
        finally:self._binding_guard=None
        # These tables may already be referenced by ordinary rules. Replaying
        # previously released warming replies is not an unreferenced startup.
        session.finish_startup()
        self.session=session;self.boot=guard.producer.boot_id;self.last_generation=guard.generation.generation
        self.generation_drops = 0
        return session

    def _record_reply_loss(self, count, utc):
        # Callback workers can capture the counter before acquiring the shared
        # socket lock. A delayed lower count cannot erase a known gap.
        if count > self.generation_drops:
            self.reported_drops = min(2**63 - 1, self.reported_drops + count - self.generation_drops)
            self.generation_drops = count
            self.last_loss_utc = utc

    def reply_loss_status(self):
        return {
            'dropped': self.reported_drops,
            'generation_dropped': self.generation_drops,
            'loss_fences_confirmations': not self.allow_reported_reply_loss,
            'last_reported_utc': self.last_loss_utc,
        }

    def detach(self):
        previous,self.session=self.session,None
        if previous is not None:
            # Permanently invalidate old ACK/mapping authority. Expiry belongs
            # to the healthy owner, so do not retire or reset its writer.
            previous.finish_startup();previous._suspend('producer_session_retired')
        return previous

    def expire(self,*,deadline):
        """Defer only a known-unexecuted lock acquisition, never renew a lease.

        A native reload also prevents the independent cleanup worker from
        acquiring this lock. Ending the feed cannot make removal happen sooner.
        Keep its healthy writer alive and retry at most twenty times per second;
        once the lock is released, tick removes every now-expired mapping using
        its original deadline. Partial writes and foreign changes still raise.
        """
        now=time.monotonic();deadline=clock(deadline)
        if not 0<deadline-now<=.1:raise ValueError('bounded future expiry deadline required')
        if self.writer.state!='ready':raise WriterSuspended('expiry writer is no longer healthy')
        if self.expiry_retry_at is not None and now<self.expiry_retry_at:return None
        try:result=self.writer.tick(deadline=deadline)
        except ReloadBusy:
            if self.writer.state!='ready':raise
            if self.writer.confirmation is not None:self.writer.confirmation.invalidate()
            if self.expiry_busy_since is None:self.expiry_busy_since=now
            self.expiry_retry_at=now+self.EXPIRY_RETRY_SECONDS
            self.expiry_deferred_update=self.writer.updates
            self.expiry_deferrals=min(2**63-1,self.expiry_deferrals+1)
            return None
        self.expiry_busy_since=self.expiry_retry_at=None
        return result

    def next_expiry_attempt(self):
        # A fresh reply may have acquired the lock and drained expiry before
        # the scheduled retry. Do not leave the UI claiming it is still busy.
        if self.expiry_retry_at is not None and self.writer.updates!=self.expiry_deferred_update:
            self.expiry_busy_since=self.expiry_retry_at=None
        deadline=self.writer.status()['next_deadline']
        return max(deadline,self.expiry_retry_at or deadline) if deadline is not None else None

    def expiry_status(self):
        return {'waiting_for_filter_lock':self.expiry_busy_since is not None,
                'busy_since_monotonic':self.expiry_busy_since,'next_attempt_monotonic':self.expiry_retry_at,
                'deferrals':self.expiry_deferrals,'retry_interval_seconds':self.EXPIRY_RETRY_SECONDS,
                'original_lease_deadlines_preserved':True}
