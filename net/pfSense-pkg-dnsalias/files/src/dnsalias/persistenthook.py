"""Same-boot hook supervision while an existing live owner changes producers.

No process discovery, source adoption, command, file path or boot recovery is
provided here. The native worker must independently qualify the replacement
watch, TLS credentials/runtime and exact recorded overlay. The original strict
HookRollbackController remains unchanged. Stop/owner loss still restores only
the known prefix against the currently qualified producer, without retry.
"""
from .hookrollback import HookRollbackController
from .hooktrial import deadline_status
from .processwatch import ProcessLifetimeWatch
import time


class PersistentHookController(HookRollbackController):
    def __init__(self,*args,qualify_resolver,**kwargs):
        if not callable(qualify_resolver):raise ValueError('independent replacement qualification required')
        super().__init__(*args,**kwargs)
        self.qualify_resolver=qualify_resolver;self.waiting_for_resolver=False;self.handoffs=0

    def arm(self):
        value=self.journal.read()
        if value is None or value['checkpoint']['plan']['duration_seconds'] is not None:
            raise ValueError('explicit persistent hook plan required')
        return super().arm()

    def follow_resolver(self,replacement):
        """One explicit handoff after confirmed exit; never follow on owner loss.

        A failed attempt terminates this controller. Native callers inspect the
        recorded outcome and must not repeat an uncertain write or reload.
        """
        if (self.state!='armed' or not self.waiting_for_resolver
            or not isinstance(replacement,ProcessLifetimeWatch) or replacement is self.resolver_watch
            or replacement.pid in (self.resolver_watch.pid,self.coordinator_watch.pid)):
            raise ValueError('distinct fresh watched replacement after resolver exit required')
        try:
            self._read_current()
            if (not self.coordinator_watch.alive() or self.resolver_watch.alive()
                or self.resolver_watch.state!='exited' or not replacement.alive()):
                raise ValueError('live original owner and confirmed old-process exit required')
            decision=deadline_status(self.value,boot_id=self.boot_id,now=time.monotonic(),utc_now=time.time())
            if decision['decision']!='waiting':raise ValueError('same live ownership lifetime required')
            installed=self.value['plan']['overlay']['installed_sha256']
            self._inspect({installed})
            if self.qualify_resolver(replacement) is not True:raise ValueError('replacement independently refused')
            self._inspect({installed})
            if not self.coordinator_watch.alive() or not replacement.alive():raise ValueError('handoff lifetime ended')
            self._record('armed','resolver_handoff')
            self.resolver_watch=replacement;self.waiting_for_resolver=False;self.handoffs+=1
        except Exception as exc:
            self._uncertain('resolver_handoff_unqualified:'+type(exc).__name__[:60]);raise
        return {'followed':True,'resolver_pid':replacement.pid,'hook_restored':False,'reload_requested':False}

    def step(self,*,stop_requested=False):
        if type(stop_requested) is not bool:raise ValueError('explicit stop decision required')
        if self.state!='armed':return self.state
        try:
            self._read_current()
            decision=deadline_status(self.value,boot_id=self.boot_id,now=time.monotonic(),utc_now=time.time())
            if decision['decision']=='inspect':self._record('conflict',decision['reason']);return self.state
            if not self.coordinator_watch.alive():return self._rollback('coordinator_lifetime_ended')
            if stop_requested:return self._rollback('operator_stop')
            if decision['decision']=='restore_due':return self._rollback(decision['reason'])
            if not self.resolver_watch.alive():
                if self.resolver_watch.state!='exited':self._record('conflict','resolver_lifetime_unqualified')
                else:self.waiting_for_resolver=True
        except Exception as exc:self._uncertain('controller_unqualified:'+type(exc).__name__[:60])
        return self.state

    def status(self):
        return super().status()|{'waiting_for_resolver':self.waiting_for_resolver,'resolver_handoffs':self.handoffs,
            'resolver_pid':self.resolver_watch.pid,'same_live_owner_only':True,'automatic_process_discovery':False}
