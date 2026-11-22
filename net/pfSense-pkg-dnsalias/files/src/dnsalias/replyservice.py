"""Inactive supervised observation lifecycle using explicitly owned resources.

No default paths, hook loading, processes, signals, PF or automatic recovery.
The caller owns the controlled load, producer/boot qualification, socket/store,
source pins, credentials and two independent process watches. Call step outside
DNS callbacks on the collector loop. close stops only this adapter and its audit
thread; borrowed resources must remain open until resources_releasable is true.
"""
from .auditworker import AuditWorker
from .collector import EventStore
from .deployment import DeploymentGuard
from .observation import ReplyObservationSession
from .observationpump import ReplyObservationPump
from .processwatch import ProcessLifetimeWatch
from .replybridge import ReplyTelemetryBridge
from .replynormalize import ReplyProfile
from .replystartup import ReplyStartup
from .runtimecontrol import RuntimeDeploymentAudit


class ReplyObservationService:
    def __init__(self,startup,*,auditor,watch,store):
        if not isinstance(startup,ReplyStartup) or startup.state!='collecting':
            raise ValueError('fresh caller-controlled reply startup required')
        if (not isinstance(auditor,RuntimeDeploymentAudit) or auditor.expected!=startup.expected
            or auditor.producer!=startup.producer or auditor.failed is not None):
            raise ValueError('matching complete runtime/source auditor required')
        if (not isinstance(watch,ProcessLifetimeWatch) or watch.pid!=startup.producer.pid
            or watch.lifetime_id!=startup.producer.process_start_id or watch is auditor.watch
            or auditor.watch.lifetime_id==watch.lifetime_id):
            raise ValueError('independent main-loop and audit process watches required')
        if (not isinstance(store,EventStore) or store.max_events<ReplyTelemetryBridge.BATCH
            or store.db.execute('PRAGMA busy_timeout').fetchone()[0]>25):
            raise ValueError('bounded telemetry writer with at most25ms lock wait required')
        self.profile=ReplyProfile(auditor.snapshot['versions']['unbound'],auditor.expected.identifier,auditor.expected.excluded_addresses)
        self.startup,self.auditor,self.watch,self.store=startup,auditor,watch,store
        self.guard=DeploymentGuard(startup.expected,startup.producer,process_watch=watch)
        self.worker=AuditWorker(auditor.capture)
        self.session=self.pump=self.bridge=None
        self.state='starting';self.reason=None;self.resources_releasable=False

    def _suspend(self,reason):
        if self.reason is None:self.reason=reason
        self.guard.suspend(reason);self.startup.close()
        if self.bridge is not None:self.bridge.close()
        self.resources_releasable=self.worker.close(wait_seconds=0)
        self.state='suspended'

    def step(self):
        """Bounded receiver/SQLite work; independent audits run on one worker.

        Startup never waits for an audit. Failures are sticky and retain stored
        history. This class never adopts a new generation or retries storage
        after an uncertain commit. A new controlled lifetime is required.
        """
        if self.state not in ('starting','running'):return self.state
        try:
            qualification=self.guard.check()
            if qualification not in ('qualified','not_audited'):
                self._suspend(qualification);return self.state
            if self.state=='starting':
                if self.startup.poll()!='collecting':
                    self._suspend(self.startup.reason or 'startup_unqualified');return self.state
                if self.startup.enrollment is None:return self.state
                if self.worker.thread is None:self.worker.start()
                qualification=self.worker.apply(self.guard)
                if qualification=='not_audited':return self.state
                if qualification!='qualified':
                    self._suspend(qualification);return self.state
                self.session=ReplyObservationSession(profile=self.profile,producer_uid=self.startup.producer.uid,
                    producer_pid=self.startup.producer.pid,deployment_guard=self.guard)
                self.pump=ReplyObservationPump(self.startup.endpoint.socket,self.session,
                    endpoint=self.startup.endpoint,startup=self.startup)
                self.bridge=ReplyTelemetryBridge(self.pump,self.store)
                self.state='running'
            else:
                qualification=self.worker.apply(self.guard)
                if qualification!='qualified':
                    self._suspend(qualification);return self.state
            self.bridge.step()
            if self.bridge.state in ('failed','suspended'):
                self._suspend(self.bridge.reason or 'reply_bridge_ended')
        except Exception as exc:
            # File contents, credentials and private paths must not leak into
            # service status. Caller can inspect private diagnostics separately.
            self._suspend('observer_step_failed:'+type(exc).__name__[:60])
        return self.state

    def close(self,*,wait_seconds=.1):
        """Bounded stop; false explicitly means borrowed resources stay owned."""
        if self.reason is None:self.reason='caller_closed'
        self.guard.suspend(self.reason);self.startup.close()
        if self.bridge is not None:self.bridge.close()
        self.resources_releasable=self.worker.close(wait_seconds=wait_seconds)
        self.state='stopped' if self.resources_releasable else 'stopping'
        return self.resources_releasable

    def status(self):
        return {'state':self.state,'reason':self.reason,'mode':'observation_only',
            'resources_releasable':self.resources_releasable,'startup':self.startup.status(),
            'audit_worker':self.worker.status(),'bridge':self.bridge.status() if self.bridge is not None else None,
            'enforcement_applied':False,'automatic_recovery':False}
