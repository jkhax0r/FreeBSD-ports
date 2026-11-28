"""Same-owner resolver transition; no foreign hook or old-table adoption.

The live writer and its deadlines stay owned throughout this transition. TLS
discovery runs outside its loop. An independent hook worker must approve the
replacement before one controlled reload and a fresh callback enrollment.
"""
import time

from .deployment import ProducerIdentity
from .processwatch import ProcessLifetimeWatch
from .replystartup import ReplyStartup
from .resolverreplacement import ResolverReplacement,source_identity,unchanged_reader_sources
from .runtimecontrol import RuntimeDeploymentAudit
from .sourceaudit import SourceAudit,SourceChanged
from .replywriterpump import ReplyDestination


class ResolverHandoff:
    def __init__(self,*,feed,service,probe,watch,audit_watch,operation,control,sources,
                 specs,ancestors,identity,snapshot,credentials,target,boot_id,probe_factory,observer_configuration):
        if (not feed.persistent or watch.alive() or watch.state!='exited'
            or service.startup.enrollment is None or not operation.persistent):
            raise ValueError('live persistent owner and confirmed enrolled resolver exit required')
        self.feed,self.service,self.probe=feed,service,probe
        self.old_watch,self.old_audit_watch=watch,audit_watch
        self.operation,self.control,self.sources=operation,control,sources
        self.original_sources=sources
        self.specs,self.ancestors,self.identity=specs,ancestors,identity
        self.snapshot,self.credentials,self.target=snapshot,credentials,target
        self.observer_configuration=dict(observer_configuration)
        self.boot_id,self.probe_factory=boot_id,probe_factory
        self.retired=service.startup.enrollment
        self.state='draining';self.search=None;self.watch=self.audit_watch=None
        self.started=time.monotonic();self.completed=None
        self.confirmation_prepared=False
        if feed.confirmation_owner is not None:
            self.confirmation_prepared=feed.confirmation_owner.prepare_replacement(watch)
        # No new mappings can enter through the retired session. Its healthy
        # persistent writer remains responsible for the old independent leases.
        self.probe.close(wait_seconds=0);self.service.close(wait_seconds=0)

    def step(self):
        self.feed.expire()
        if self.state=='draining':
            if not self.probe.close(wait_seconds=0) or not self.service.close(wait_seconds=0):
                if time.monotonic()-self.started>2:raise TimeoutError('old receiver did not release resources')
                return None
            # The old producer is confirmed dead and its receiver is closed.
            # Native reconfiguration may now be rewriting the config. Compare
            # a fresh, complete capture after the replacement starts instead
            # of interpreting that expected write as a live-code mutation.
            self.old_audit_watch.close();self.feed.retire_paths()
            self.search=ResolverReplacement(old_watch=self.old_watch,specs=self.specs,
                ancestors=self.ancestors,identity=self.identity,snapshot=self.snapshot,
                credential_directory=self.target['control_directory'],credential_uid=self.target['control_uid'],
                credential_gid=self.target['control_gid'],credential_id=self.credentials['credential_id'],
                control_port=self.target['control_port'],wait_for_status=True)
            self.search.start();self.state='discovering'
        if self.state=='discovering':
            result=self.search.status()
            if result['thread_alive'] or result['state'] in ('new','searching'):return None
            if result['state']!='qualified':raise ValueError('replacement qualification: '+str(result.get('error')))
            if 'resolver_config_metadata' in result:
                expected=dict(self.identity)|{'files':dict(self.identity['files'])}
                expected['files']['resolver_config']=tuple(result['resolver_config_metadata'])
                fresh=SourceAudit(self.specs,ancestor_uids=self.ancestors)
                try:
                    if source_identity(fresh)!=expected:
                        raise ValueError('replacement sources changed after qualification')
                except Exception:
                    fresh.close();raise
                self.sources.close();self.sources=fresh;self.identity=expected
            self.sources.audit()
            self.watch=ProcessLifetimeWatch(result['pid'])
            self.operation.request_follow(self.watch);self.state='following'
        if self.state=='following':
            if self.operation.poll_follow() is None:return None
            self.sources.audit()
            self.audit_watch=ProcessLifetimeWatch(self.watch.pid)
            producer=ProducerIdentity(self.watch.pid,self.target['control_uid'],self.boot_id,self.watch.lifetime_id)
            auditor=RuntimeDeploymentAudit(self.snapshot,producer,sources=self.sources,watch=self.audit_watch,
                control=self.control,observer_configuration=self.observer_configuration,
                credential_directory=self.target['control_directory'],credential_uid=self.target['control_uid'],
                credential_gid=self.target['control_gid'],credential_id=self.credentials['credential_id'],
                runtime_interval_seconds=self.service.auditor.runtime_interval)
            opened=time.monotonic()
            startup=ReplyStartup(self.service.startup.endpoint,expected=self.service.startup.expected,
                producer=producer,load_open=opened,retired_generation=self.retired,discard_before_load=True)
            self.service=self.feed.start(startup,auditor=auditor,watch=self.watch,data=self.target['data'],
                session=self.operation.plan['trial_id'],producer_gid=self.target['control_gid'])
            if self.confirmation_prepared:
                self.feed.before_reload(producer_pid=self.watch.pid,profile_id=startup.expected.identifier,sources=self.sources)
            self.probe=self.probe_factory(self.target|{'resolver_pid':self.watch.pid},self.control,opened,reload_before_query=True)
            self.probe.start();self.state='enrolling'
        if self.state=='enrolling':
            self.service.step();self.feed.collect()
            if self.service.startup.enrollment is not None:self.probe.observed.set()
            if self.service.state not in ('starting','running'):
                raise ValueError('replacement enrollment: '+str(self.service.reason))
            if self.service.state=='running':
                self.completed=time.monotonic();self.state='complete'
                # Old-generation route receipts were retired before replacing
                # watches. Do not accumulate one kqueue per resolver restart.
                self.old_watch.close()
                return {'service':self.service,'probe':self.probe,'watch':self.watch,'audit_watch':self.audit_watch,
                        'startup':self.service.startup,'pid':self.watch.pid,'seconds':self.completed-self.started,
                        'sources':self.sources,'source_identity':self.identity}
        return None

    def status(self):
        return {'phase':self.state,'old_pid':self.old_watch.pid,
                'replacement':None if self.search is None else self.search.status()}

    def close(self):
        released=self.search is None or self.search.close(wait_seconds=1)
        if self.state!='complete':
            released=self.probe.close(wait_seconds=0) and released
            released=self.service.close(wait_seconds=0) and released
            if released and self.audit_watch is not None:self.audit_watch.close()
            # ObservationTrial may still hold this watch for its independent
            # worker outcome. Caller closes the operation before releasing it.
            if released and self.watch is not None:self.watch.close()
            if self.sources is not self.original_sources:self.sources.close()
        return released


class ResolverReloadHandoff:
    """Retired reader transition; PID exit still uses the original exit gate.

    Same-PID continuation requires authenticated retirement AND a fresh hello,
    exact unchanged source identities, current TLS settings, a fresh generation
    and a post-load audit. The existing writer keeps its original deadlines.
    """
    def __init__(self,*,feed,service,probe,watch,audit_watch,operation,control,sources,
                 specs,ancestors,identity,snapshot,credentials,target,boot_id,probe_factory,observer_configuration,proof):
        owner=feed.confirmation_owner
        if (not feed.persistent or owner is None or proof is not owner.pending_reload
            or service.startup.enrollment is None or service.reason not in (None,'reply_endpoint_changed')
            or not watch.alive() or proof['watch_lifetime']!=watch.lifetime_id):
            raise ValueError('authenticated live-reader retirement required')
        self.arguments=dict(feed=feed,service=service,probe=probe,watch=watch,audit_watch=audit_watch,operation=operation,
            control=control,sources=sources,specs=specs,ancestors=ancestors,identity=identity,snapshot=snapshot,
            credentials=credentials,target=target,boot_id=boot_id,probe_factory=probe_factory,observer_configuration=observer_configuration)
        self.feed,self.service,self.probe=feed,service,probe
        self.watch,self.old_audit_watch,self.sources=watch,audit_watch,sources
        self.owner,self.proof=owner,proof;self.retired=service.startup.enrollment
        self.state='waiting_for_reader';self.delegate=None;self.new_audit_watch=None;self.startup=None
        self.warm_route=None;self.warming_acks=0;self.started=proof['retired']['observed_monotonic']
        self.old_service,self.old_probe=service,probe
        self.original_sources=sources
        self.probe.close(wait_seconds=0);self.service.close(wait_seconds=0)

    def _warming(self,event,credentials):
        if self.warm_route is None:
            self.warm_route=ReplyDestination(self.feed.ack/('g-'+self.startup.enrollment.generation),
                uid=self.startup.producer.uid,gid=self.arguments['target']['control_gid'],socket_count=self.feed.socket_count)
        sent=self.warm_route.send(self.startup.endpoint,{'request_id':event['request_id'],'status':'ignored'},
            deadline=event['monotonic']+.04)
        if sent!='queued':return False
        self.warming_acks+=1;return True

    def step(self):
        self.feed.expire()
        if self.delegate is not None:
            result=self.delegate.step()
            self.service,self.probe=self.delegate.service,self.delegate.probe
            if result is not None:self.state='complete';result['kind']='process_replacement'
            return result
        if not self.watch.alive():
            if self.state!='waiting_for_reader' or self.watch.state!='exited':raise ValueError('resolver ended during reader enrollment')
            # This keeps the old confirmed-process-exit predicate unchanged.
            self.delegate=ResolverHandoff(**self.arguments);self.state='process_replacement'
            return self.step()
        if time.monotonic()-self.started>=ReplyStartup.MAX_SECONDS:raise TimeoutError('reader reload enrollment deadline')
        if self.state=='waiting_for_reader':
            self.owner.poll_reload(self.watch,self.retired)
            if self.proof['hello'] is None:return None
            # Pin and hash the complete set again while the old reader is
            # retired. Only the timestamps of the same pinned config inode
            # may differ. Every executable source and ancestor remains exact.
            prior=self.arguments['identity']
            fresh=SourceAudit(self.arguments['specs'],ancestor_uids=self.arguments['ancestors'])
            try:
                observed=source_identity(fresh)
                target=self.arguments['target']
                if not unchanged_reader_sources(prior,observed,self.arguments['specs'],
                                                target['control_uid'],target['control_gid']):
                    for key in ('hashes','files','directories'):
                        for name in sorted(prior[key].keys() | observed[key].keys()):
                            if prior[key].get(name)!=observed[key].get(name):
                                raise SourceChanged('reader reload '+key+' changed: '+name)
                    raise SourceChanged('reader reload source set changed')
                if self.proof['retired']['kind']=='reader_retired_config_check' and observed==prior:
                    raise SourceChanged('reader watch changed without a resolver config renewal')
            except BaseException:
                fresh.close()
                raise
            self.sources=fresh
            self.arguments['identity']=observed
            self.owner.prepare_reconfiguration(self.proof,self.watch,self.retired,self.sources)
            producer=ProducerIdentity(self.watch.pid,self.arguments['target']['control_uid'],self.arguments['boot_id'],self.watch.lifetime_id)
            self.startup=ReplyStartup(self.old_service.startup.endpoint,expected=self.old_service.startup.expected,
                producer=producer,load_open=self.started,retired_generation=self.retired,discard_before_load=True,
                required_generation=self.proof['hello']['resolver_generation'])
            # Donation can unblock the new Python init while the old read-only
            # audit thread finishes. The page stays revoked; staging sends only
            # ignored ACKs and never mutates or replays a mapping.
            self.feed.before_reload(producer_pid=self.watch.pid,profile_id=self.startup.expected.identifier,
                sources=self.sources,expected_generation=self.startup.required_generation)
            self.state='quiescing'
        if self.state=='quiescing':
            if self.startup.poll(on_staged=self._warming)!='collecting':raise ValueError('reader reload staging: '+str(self.startup.reason))
            released=self.old_probe.close(wait_seconds=0) and self.old_service.close(wait_seconds=0)
            if not released:return None
            self.original_sources.close()
            self.old_audit_watch.close();self.feed.retire_paths()
            self.new_audit_watch=ProcessLifetimeWatch(self.watch.pid)
            auditor=RuntimeDeploymentAudit(self.arguments['snapshot'],self.startup.producer,sources=self.sources,
                watch=self.new_audit_watch,control=self.arguments['control'],observer_configuration=self.arguments['observer_configuration'],
                credential_directory=self.arguments['target']['control_directory'],credential_uid=self.arguments['target']['control_uid'],
                credential_gid=self.arguments['target']['control_gid'],credential_id=self.arguments['credentials']['credential_id'],
                runtime_interval_seconds=self.old_service.auditor.runtime_interval)
            self.service=self.feed.start(self.startup,auditor=auditor,watch=self.watch,data=self.arguments['target']['data'],
                session=self.arguments['operation'].plan['trial_id'],producer_gid=self.arguments['target']['control_gid'])
            if self.warm_route is not None:
                self.service.accept_warming_route(self.warm_route,acknowledgments=self.warming_acks);self.warm_route=None
            self.probe=self.arguments['probe_factory'](self.arguments['target'],self.arguments['control'],self.started)
            self.probe.start();self.state='enrolling'
        if self.state=='enrolling':
            self.service.step();self.feed.collect()
            if self.startup.enrollment is not None:self.probe.observed.set()
            if self.service.state not in ('starting','running'):raise ValueError('reader reload qualification: '+str(self.service.reason))
            if self.service.state=='running':
                if self.owner.state!='enrolled' or self.owner.enrolled_generation!=self.startup.required_generation:
                    raise ValueError('fresh reader source-watch enrollment incomplete')
                self.state='complete'
                return {'service':self.service,'probe':self.probe,'watch':self.watch,'audit_watch':self.new_audit_watch,
                    'startup':self.startup,'pid':self.watch.pid,'seconds':time.monotonic()-self.started,'kind':'same_pid_reload',
                    'sources':self.sources,'source_identity':self.arguments['identity']}
        return None

    def status(self):
        value={'phase':self.state,'old_pid':self.watch.pid,'same_pid_protocol':True,
               'fresh_reader_announced':self.proof['hello'] is not None}
        # A reader retirement can turn into a confirmed process exit. Keep
        # the existing worker's bounded refusal reason and source-change
        # labels visible instead of reducing that failure to ValueError.
        if self.delegate is not None:value['replacement_handoff']=self.delegate.status()
        return value

    def close(self):
        if self.delegate is not None:return self.delegate.close()
        if self.warm_route is not None:self.warm_route.close();self.warm_route=None
        if self.state=='complete':return True
        released=self.probe.close(wait_seconds=0) and self.service.close(wait_seconds=0)
        if self.old_service is not self.service:released=self.old_service.close(wait_seconds=0) and released
        if released and self.new_audit_watch is not None:self.new_audit_watch.close()
        if released and self.sources is not self.original_sources:self.sources.close()
        return released
