"""Inactive writer lifecycle using explicit borrowed, already-owned resources.

Rules must remain disarmed throughout startup. Caller owns hook loading, process
supervision, table/endpoint provisioning, native filter lifecycle and independent
cleanup. Periodic table audits are explicit opt-in and run in the owner loop
after an observed drained queue; they can delay newly arriving DNS work. This
class starts only a bounded source/runtime audit thread;
it never starts a process, activates a hook/rule, writes SQLite or retires tables.
"""
import time
import math

from .auditworker import AuditWorker
from .deployment import DeploymentGuard
from .pfwriter import LeaseTableWriter
from .processwatch import ProcessLifetimeWatch
from .replynormalize import ReplyProfile
from .replyowner import PersistentReplyOwner
from .replystartup import ReplyStartup
from .replywriter import ReplyWriterSession
from .replywriterpump import ReplyDestination,ReplyWriterPump
from .runtimecontrol import RuntimeDeploymentAudit
from .reloadlock import ReloadBusy


class ReplyWriterService:
    PRIME_BUDGET=.04

    def __init__(self,startup,*,auditor,watch,writer,reply_directory,producer_gid,table_audit_interval=None,
                 lease_owner=None,per_generation=False,socket_count=1):
        if table_audit_interval is not None and (type(table_audit_interval) not in (int,float)
            or not math.isfinite(table_audit_interval) or not 1<=table_audit_interval<=3):
            raise ValueError('explicit table audit interval must be1..3seconds or disabled')
        if not isinstance(startup,ReplyStartup) or startup.state!='collecting':raise ValueError('fresh controlled startup required')
        if (not isinstance(auditor,RuntimeDeploymentAudit) or auditor.expected!=startup.expected
            or auditor.producer!=startup.producer or auditor.failed is not None):
            raise ValueError('matching complete source/runtime auditor required')
        if (not isinstance(watch,ProcessLifetimeWatch) or watch.pid!=startup.producer.pid
            or watch.lifetime_id!=startup.producer.process_start_id or watch is auditor.watch
            or watch.lifetime_id==auditor.watch.lifetime_id):
            raise ValueError('independent main and audit lifetime watches required')
        if type(per_generation) is not bool:raise ValueError('explicit generation endpoint mode required')
        if socket_count!=1 and not per_generation:raise ValueError('worker sockets require a generation')
        owned=(type(lease_owner) is PersistentReplyOwner and lease_owner.writer is writer
            and lease_owner.session is None)
        if (lease_owner is not None and not owned):raise ValueError('detached persistent writer owner required')
        claimed=getattr(writer,'_persistent_reply_owner',None)
        if (not isinstance(writer,LeaseTableWriter) or writer.state!='ready'
            or (not owned and (writer.updates or writer.writer.total or claimed is not None))
            or type(producer_gid) is not int or not 0<=producer_gid<2**32):
            raise ValueError('fresh empty borrowed writer and explicit producer group required')
        self.startup,self.auditor,self.watch,self.writer=startup,auditor,watch,writer
        self.directory,self.gid=reply_directory,producer_gid
        self.lease_owner,self.per_generation=lease_owner,per_generation
        self.socket_count=socket_count
        self.profile=ReplyProfile(auditor.snapshot['versions']['unbound'],startup.expected.identifier,startup.expected.excluded_addresses)
        self.guard=DeploymentGuard(startup.expected,startup.producer,process_watch=watch)
        self.worker=AuditWorker(auditor.capture);self.route=self.session=self.pump=None
        self.state='starting';self.reason=None;self.resources_releasable=False
        self.outcomes=[];self.warming_acks=0;self.replayed=0;self.telemetry_unconsumed=0;self.warming_discarded=0
        self.table_audit_interval=table_audit_interval;self.last_table_audit=None;self.table_audits=0
        self.audit_busy_since=None;self.next_audit_attempt=None;self.audit_deferrals=0

    def _audit_tables(self):
        if self.socket_count>1 and not self.route.audit():
            self._suspend('reply_endpoint_changed')
            return
        started=time.monotonic()
        try:audited=self.session.audit(deadline=started+.04)
        except ReloadBusy:
            # Only an unexecuted lock acquisition reaches here. Keep the old
            # audit/lease timestamps and reject new mapping acknowledgements
            # until a real table audit succeeds. The source/lifetime guards
            # remain active; changed tables still suspend the writer.
            if self.audit_busy_since is None:self.audit_busy_since=started
            self.next_audit_attempt=started+.05;self.audit_deferrals+=1
            self.session.table_audit_pending=True
        else:
            if not audited:self._suspend(self.session.reason or 'table_audit_unavailable')
            else:
                self.last_table_audit=started;self.table_audits+=1
                self.audit_busy_since=self.next_audit_attempt=None
                self.session.table_audit_pending=False

    def _warming(self,event,credentials):
        if self.route is None:
            directory=self.directory
            if self.per_generation:
                # ReplyStartup has already checked native credentials and
                # enrolled this canonical generation inside our load window.
                # Never accept a reply-supplied path or use an old ACK socket.
                from pathlib import Path
                directory=Path(directory)/('g-'+self.startup.enrollment.generation)
            self.route=ReplyDestination(directory,uid=self.startup.producer.uid,gid=self.gid,socket_count=self.socket_count)
        sent=self.route.send(self.startup.endpoint,{'request_id':event['request_id'],'status':'ignored'},
            deadline=event['monotonic']+self.PRIME_BUDGET)
        if sent!='queued':return False
        self.warming_acks+=1;return True

    def accept_warming_route(self,route,*,acknowledgments):
        """Transfer a staged ignored-only route; no mappings are replayed."""
        from pathlib import Path
        enrollment=self.startup.enrollment
        if (self.state!='starting' or self.route is not None or self.session is not None or self.pump is not None
            or self.worker.thread is not None or enrollment is None or not self.per_generation
            or type(route) is not ReplyDestination or len(route.names)!=self.socket_count or not route.audit()
            or route.directory!=Path(self.directory)/('g-'+enrollment.generation)
            or (route.uid,route.gid)!=(self.startup.producer.uid,self.gid)
            or type(acknowledgments) is not int or not 1<=acknowledgments<=self.startup.MAX_EVENTS):
            raise ValueError('exact staged fresh-generation route required')
        self.route=route;self.warming_acks=acknowledgments

    def _suspend(self,reason):
        if self.reason is None:self.reason=reason
        self.guard.suspend(self.reason);self.startup.close()
        if self.session is not None:self.session._suspend(self.reason)
        if self.lease_owner is not None and self.lease_owner.session is self.session:self.lease_owner.detach()
        if self.pump is not None:self.pump._stop(self.reason)
        if self.route is not None:self.route.close()
        self.resources_releasable=self.worker.close(wait_seconds=0)
        self.state='suspended'

    def step(self):
        """Nonblocking receiver/audit consumption; bounded startup replay.

        Priming has one shared40ms budget, including its initial empty-table
        audit. If it cannot finish, the service stays unqualified and needs
        independent cleanup; it does not extend deadlines or retry. During
        running, idle expiry occurs only when a known lease becomes due. Optional
        periodic table checks prefer a drained queue, then run before receive
        after one second of deferral. Native reload contention holds mapping
        acknowledgements until the exact table check can complete.
        """
        if self.state not in ('starting','running'):return self.state
        try:
            if self.lease_owner is not None:
                # Retained leases expire even while the new producer is still
                # enrolling. Expiry does not require a live DNS process.
                now=time.monotonic();expiry=self.lease_owner.next_expiry_attempt()
                if expiry is not None and expiry<=now:self.lease_owner.expire(deadline=now+.04)
            if self.state=='running' and self.table_audit_interval is not None:
                if self.session.table_audit_pending:
                    if time.monotonic()>=self.next_audit_attempt:self._audit_tables()
                    if self.state!='running':return self.state
                elif time.monotonic()>=self.last_table_audit+self.table_audit_interval+1:
                    # Bound queue deferral without stopping a healthy feed.
                    # Audit before receiving; only an unexecuted reload lock
                    # may defer further, with mapping ACKs held meanwhile.
                    self._audit_tables()
                    if self.state!='running':return self.state
            qualification=self.guard.check()
            if qualification not in ('qualified','not_audited'):
                self._suspend(qualification);return self.state
            if self.state=='starting':
                if self.startup.poll(on_staged=self._warming)!='collecting':
                    self._suspend(self.startup.reason or 'startup_unqualified');return self.state
                if self.startup.enrollment is None:return self.state
                if self.worker.thread is None:self.worker.start()
                qualification=self.worker.apply(self.guard)
                if qualification=='not_audited':return self.state
                if qualification!='qualified':self._suspend(qualification);return self.state
                queue,assembler=self.startup.take(self.guard)
                deadline=time.monotonic()+self.PRIME_BUDGET
                audit_started=time.monotonic()
                if self.lease_owner is None:
                    self.session=ReplyWriterSession(profile=self.profile,guard=self.guard,writer=self.writer)
                    self.writer.audit(deadline=deadline)
                else:
                    self.session=self.lease_owner.bind(profile=self.profile,guard=self.guard,deadline=deadline)
                self.last_table_audit=audit_started;self.table_audits+=1
                for event,credentials in queue:
                    if self.lease_owner is not None:
                        # A warming reply was already released with ignored.
                        # Referenced tables cannot grant it retroactively.
                        self.warming_discarded+=1;continue
                    if time.monotonic()>=deadline:raise TimeoutError('startup replay budget')
                    result=self.session.replay_startup(event,credentials,deadline=deadline)
                    if result['reason'] not in ('startup_memberships_seeded','unsupported_startup_reply'):
                        self._suspend(result['reason']);return self.state
                    self.replayed+=1
                self.session.finish_startup()
                self.pump=ReplyWriterPump(self.startup.endpoint,self.session,self.route,assembler=assembler)
                self.state='running'
            else:
                qualification=self.worker.apply(self.guard)
                if qualification!='qualified':self._suspend(qualification);return self.state
            if self.outcomes:
                self.telemetry_unconsumed=min(2**63-1,self.telemetry_unconsumed+len(self.outcomes))
            self.outcomes=self.pump.poll()
            if self.pump.state!='ready':self._suspend(self.pump.reason or 'writer_receiver_ended');return self.state
            expiry=(self.lease_owner.next_expiry_attempt() if self.lease_owner is not None
                    else self.writer.status()['next_deadline']);now=time.monotonic()
            if expiry is not None and expiry<=now:
                if self.lease_owner is not None:self.lease_owner.expire(deadline=now+.04)
                elif not self.session.tick(deadline=now+.04):self._suspend(self.session.reason or 'idle_expiry_unavailable')
            if (self.state=='running' and self.table_audit_interval is not None and self.pump.drained
                and not self.session.table_audit_pending
                and time.monotonic()>=self.last_table_audit+self.table_audit_interval):
                self._audit_tables()
        except Exception as exc:self._suspend('writer_service_step_failed:'+type(exc).__name__[:60])
        return self.state

    def take_outcomes(self):
        """Caller consumes observations after ACK processing, before next step."""
        values,self.outcomes=self.outcomes,[];return values

    def close(self,*,wait_seconds=.1):
        if self.reason is None:self.reason='caller_closed'
        self.guard.suspend(self.reason);self.startup.close()
        if self.session is not None:self.session._suspend(self.reason)
        if self.lease_owner is not None and self.lease_owner.session is self.session:self.lease_owner.detach()
        if self.pump is not None:self.pump._stop(self.reason)
        if self.route is not None:self.route.close()
        self.resources_releasable=self.worker.close(wait_seconds=wait_seconds)
        self.state='stopped' if self.resources_releasable else 'stopping'
        return self.resources_releasable

    def status(self):
        return {'state':self.state,'reason':self.reason,'resources_releasable':self.resources_releasable,
            'warming_acks':self.warming_acks,'startup_replayed':self.replayed,
            'warming_discarded':self.warming_discarded,'persistent_lease_owner':self.lease_owner is not None,
            'expiry':self.lease_owner.expiry_status() if self.lease_owner is not None else None,
            'generation_ack_endpoint':self.per_generation,
            'telemetry_unconsumed':self.telemetry_unconsumed,'audit_worker':self.worker.status(),
            'table_audit':{'interval_seconds':self.table_audit_interval,'completed':self.table_audits,
                'last_started_monotonic':self.last_table_audit,'max_deferral_seconds':1,
                'waiting_for_filter_lock':self.audit_busy_since is not None,
                'busy_since_monotonic':self.audit_busy_since,'next_attempt_monotonic':self.next_audit_attempt,
                'reload_deferrals':self.audit_deferrals,'reload_retry_seconds':.05,
                'mapping_acks_held_until_audited':True,
                'operation_budget_seconds':.04,'prefer_drained_queue':True,
                'overdue_check_before_receive':True},
            'pump':self.pump.status() if self.pump is not None else None,'writer':self.writer.status(),
            'independent_cleanup_required':self.state in ('suspended','stopping','stopped'),
            'rules_managed':False,'production_enforcement_qualified':False,'automatic_recovery':False}
