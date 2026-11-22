"""Inactive rollback orchestration for a separately supervised local process.

Caller must run this independently, own the journal and native process watches,
and supply qualified bounded inspection/restoration/reload/verification actions
bound to the immutable plan. No command, path, process creation or signal is
built in. Callback results are caller evidence, not independent attestation.
The fixed production adapter and native writer coordination remain required.

Emit readiness over the actual child pipe ONLY after arm() returns successfully.
An on-disk armed phase alone cannot prove successful durable arming: a directory
sync error may occur after rename. The loader must also watch this process.
"""
import copy
import os
import time
import uuid

from .checkpoint import identity
from .hooktrial import HookTrialFile,deadline_status
from .processwatch import ProcessLifetimeWatch


class HookRollbackController:
    def __init__(self,journal,*,boot_id,coordinator_watch,resolver_watch,inspect,restore,reload,verify_loaded):
        identity(boot_id)
        if not isinstance(journal,HookTrialFile):raise ValueError('explicit owned trial journal required')
        if (not isinstance(coordinator_watch,ProcessLifetimeWatch) or not isinstance(resolver_watch,ProcessLifetimeWatch)
            or coordinator_watch is resolver_watch or coordinator_watch.pid==resolver_watch.pid):
            raise ValueError('independent coordinator and resolver lifetime watches required')
        if not all(callable(action) for action in (inspect,restore,reload,verify_loaded)):
            raise ValueError('explicit bounded qualified actions required')
        self.journal,self.boot_id=journal,boot_id
        self.coordinator_watch,self.resolver_watch=coordinator_watch,resolver_watch
        self.inspect_action,self.restore_action,self.reload_action,self.verify_action=inspect,restore,reload,verify_loaded
        self.worker={'pid':os.getpid(),'epoch':uuid.uuid4().hex}
        self.value=None;self.digest=None;self.state='new';self.reason=None;self.observed_hook_sha256=None

    def _read_current(self):
        result=self.journal.read()
        if result is None:raise ValueError('trial intention missing')
        if self.digest is not None and result['file_sha256']!=self.digest:raise ValueError('trial journal changed')
        return result

    def _inspect(self,allowed):
        result=self.inspect_action(copy.deepcopy(self.value['plan']))
        if type(result) is not dict or set(result)!={'hook_sha256','config_sha256'}:
            raise ValueError('complete independent hook/config inspection required')
        identity(result['hook_sha256']);identity(result['config_sha256'])
        self.observed_hook_sha256=result['hook_sha256']
        if result['config_sha256']!=self.value['plan']['config_sha256']:raise ValueError('resolver configuration changed')
        if result['hook_sha256'] not in allowed:raise ValueError('hook content changed')
        return result

    def _record(self,phase,reason=None):
        value=copy.deepcopy(self.value)
        value['status'].update(phase=phase,worker=dict(self.worker),updated_monotonic=time.monotonic(),updated_utc=time.time(),reason=reason)
        digest=self.journal.save(value,expected_digest=self.digest)
        self.value,self.digest=value,digest
        self.state=phase;self.reason=reason

    def _uncertain(self,reason):
        # A mutating callback may already have completed. Inspect once for
        # evidence, but never use that observation to retry an action here.
        if self.value is not None:
            try:self._inspect({self.value['plan']['overlay']['original_sha256'],self.value['plan']['overlay']['installed_sha256']})
            except Exception:pass
        try:
            self._read_current()
            if self.value is not None and self.value['status']['phase'] not in ('complete','conflict','uncertain'):
                self._record('uncertain',reason)
        except Exception:pass
        self.state='uncertain';self.reason=reason

    def arm(self):
        if self.state!='new':raise ValueError('rollback controller cannot be rearmed')
        try:
            result=self._read_current();self.value,self.digest=result['checkpoint'],result['file_sha256']
            if self.value['status']['phase']!='prepared':raise ValueError('new prepared trial required')
            decision=deadline_status(self.value,boot_id=self.boot_id,now=time.monotonic(),utc_now=time.time())
            if decision['decision']!='waiting':raise ValueError('trial deadline or boot unqualified')
            if not self.coordinator_watch.alive() or not self.resolver_watch.alive():raise ValueError('controlled process lifetime ended')
            self._inspect({self.value['plan']['overlay']['original_sha256']})
            self._record('armed')
        except Exception as exc:
            # Do not issue a readiness acknowledgement or mutate a hook after
            # an uncertain journal write, even if armed is visible on disk.
            self.state='uncertain';self.reason='arming_unqualified:'+type(exc).__name__[:60]
            raise
        return {'ready':True,'trial_id':self.value['plan']['trial_id'],'worker':dict(self.worker)}

    def _rollback(self,reason):
        self._read_current()
        if not self.resolver_watch.alive():
            self._record('conflict','resolver_lifetime_ended');return self.state
        owned=self.value['plan']['overlay']
        try:self._inspect({owned['original_sha256'],owned['installed_sha256']})
        except Exception:
            self._record('conflict','hook_or_config_changed');return self.state
        self._record('restoring',reason)
        try:
            self.restore_action(copy.deepcopy(self.value['plan']))
            self._inspect({owned['original_sha256']})
            self._record('restored',reason)
            if not self.resolver_watch.alive():
                self._record('uncertain','resolver_lifetime_ended_after_restore');return self.state
            self._inspect({owned['original_sha256']})
            self.reload_action(copy.deepcopy(self.value['plan']))
            if not self.resolver_watch.alive() or self.verify_action(copy.deepcopy(self.value['plan'])) is not True:
                self._record('uncertain','restored_reload_unverified');return self.state
            self._inspect({owned['original_sha256']})
            self._record('complete',reason)
        except Exception as exc:self._uncertain('rollback_unqualified:'+type(exc).__name__[:60])
        return self.state

    def step(self,*,stop_requested=False):
        if type(stop_requested) is not bool:raise ValueError('explicit stop decision required')
        if self.state!='armed':return self.state
        try:
            self._read_current()
            decision=deadline_status(self.value,boot_id=self.boot_id,now=time.monotonic(),utc_now=time.time())
            if decision['decision']=='inspect':
                self._record('conflict',decision['reason']);return self.state
            if not self.coordinator_watch.alive():return self._rollback('coordinator_lifetime_ended')
            if stop_requested:return self._rollback('operator_stop')
            if decision['decision']=='restore_due':return self._rollback(decision['reason'])
            if not self.resolver_watch.alive():self._record('conflict','resolver_lifetime_ended')
        except Exception as exc:self._uncertain('controller_unqualified:'+type(exc).__name__[:60])
        return self.state

    def status(self):
        return {'state':self.state,'reason':self.reason,'worker':dict(self.worker),
            'observed_hook_sha256':self.observed_hook_sha256,'automatic_retry':False,
            'qualification':'caller-bound actions; native deployment and writer coordination required'}
