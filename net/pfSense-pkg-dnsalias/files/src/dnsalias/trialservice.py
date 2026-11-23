"""Explicit bounded observation trial using the installed qualified components.

No automatic startup, persistent installation, PF write or policy Apply route.
Caller stages a verified package/data directory, inspects all target sources,
and supplies their expected hashes. Existing resolver configuration is never
edited. The selected Python hook must already exist. DNS reloads can interrupt
queries while the native policy loads; command acknowledgement is not readiness.
The caller owns any later package removal and must inspect uncertain outcomes.
"""
import json
import ipaddress
import os
from pathlib import Path
import platform
import re
import select
import subprocess
import sys
import threading
import time
import traceback
import uuid

from .bootidentity import capture
from .collector import EventStore
from .deployment import BASE_SOURCES,PFB_SOURCES,DeploymentFingerprint,ProducerIdentity
from .dnscheck import query
from .hookbuild import render_observer,configuration_fingerprint
from .hookplan import render
from .hooktrial import prepare
from .processwatch import ProcessLifetimeWatch
from .replyservice import ReplyObservationService
from .replystartup import ReplyStartup
from .runtimecontrol import RuntimeControl,RuntimeDeploymentAudit,load_credentials
from .sourceaudit import SourceAudit,SourceChanged,SourceSpec
from .trialcoordinator import ObservationTrial
from .trialendpoint import TrialEndpoint
from .trialworker import validate_context,await_control


COMPONENTS={'observer_source':'observerhook.py','dispatcher_source':'dispatch.py',
    'extractor_source':'replyextract.py','transport_source':'ipc.py','hook_builder_source':'hookbuild.py'}


class _EnrollmentProbe:
    """Bounded off-path loopback queries; only authenticated callbacks enroll.

    Use the first already-verified rollback probe, at most four times within
    the existing startup deadline. No artificial generation/TTL extension or
    success inference from a DNS answer. Its own native watch avoids sharing a
    kqueue across threads. Cancellation interrupts read-only readiness polling.
    """
    def __init__(self,target,control,load_open,*,reload_before_query=False,persistent_start=False):
        if type(reload_before_query) is not bool:raise ValueError('explicit controlled-reload choice required')
        self.reload_before_query=reload_before_query
        if type(persistent_start) is not bool or persistent_start and reload_before_query:
            raise ValueError('initial service enrollment and replacement are separate operations')
        self.persistent_start=persistent_start
        self.pid=target['resolver_pid'];self.port=target['dns_port'];self.probe=dict(target['probes'][0])
        self.control=control
        self.deadline=load_open+(ReplyStartup.REPLACEMENT_SECONDS if reload_before_query else ReplyStartup.MAX_SECONDS)
        if persistent_start:self.deadline=load_open+ReplyStartup.INITIAL_SERVICE_SECONDS
        self.cancelled=threading.Event();self.observed=threading.Event()
        self.result={'state':'pending','queries_issued':0,'answers_received':0,'error':None}
        self.thread=threading.Thread(target=self._run,name='dnsalias-startup-probe',daemon=True)

    def _run(self):
        result={'state':'running','queries_issued':0,'answers_received':0,'error':None}
        self.result=dict(result)
        try:
            with ProcessLifetimeWatch(self.pid) as watch:
                probe=self
                class CancelWatch:
                    pid=watch.pid
                    def alive(self):return not probe.cancelled.is_set() and watch.alive()
                if self.cancelled.is_set():result['state']='cancelled';return
                remaining=self.deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('existing startup deadline expired')
                result['stage']='initial_control'
                limit=ReplyStartup.INITIAL_SERVICE_SECONDS if self.persistent_start else ReplyStartup.MAX_SECONDS
                result['initial_readiness']=await_control(self.control,CancelWatch(),budget_seconds=min(limit,remaining),persistent_start=self.persistent_start)
                if self.reload_before_query:
                    from .reloadrequest import ReloadRequest
                    if self.cancelled.is_set():result['state']='cancelled';return
                    result['stage']='sending_reload'
                    result['reload']=ReloadRequest(self.control,watch).send()
                    result['stage']='replacement_control'
                    remaining=self.deadline-time.monotonic()
                    if remaining<=0:raise TimeoutError('replacement reload readiness deadline')
                    result['replacement_readiness']=await_control(self.control,CancelWatch(),
                        budget_seconds=remaining,replacement_reload=True)
                result['stage']='loopback_probe'
                for _ in range(4):
                    remaining=self.deadline-time.monotonic()
                    if self.cancelled.is_set() or self.observed.is_set() or remaining<=0:break
                    if not watch.alive():raise ValueError('resolver ended before local enrollment probe')
                    result['queries_issued']+=1
                    query(self.probe['name'],kind=self.probe['kind'],port=self.port,timeout_seconds=min(.2,remaining))
                    result['answers_received']+=1
                    if self.observed.wait(min(.2,max(0,self.deadline-time.monotonic()))):break
                result['state']='cancelled' if self.cancelled.is_set() else 'finished'
        except Exception as exc:
            result.update(state='cancelled' if self.cancelled.is_set() else 'failed',error=type(exc).__name__)
        finally:self.result=dict(result)

    def start(self):self.thread.start()

    def close(self,wait_seconds=.5):
        self.cancelled.set()
        if self.thread.ident is not None:self.thread.join(timeout=wait_seconds)
        return not self.thread.is_alive()

    def status(self):
        return dict(self.result)|{'callback_observed':self.observed.is_set(),'thread_alive':self.thread.is_alive(),
            'purpose':'Bounded loopback startup probe; DNS answer alone never qualifies the reply feed'}


def validate_target(target):
    context_keys={'root','data','resolver_pid','control_directory','control_uid','control_gid','control_port','dns_port','probes'}
    fields=context_keys|{'format','sources','expected_sources','versions','mode','excluded_addresses','duration_seconds'}
    if type(target) is not dict or set(target)!=fields or target['format']!='dnsalias-observation-trial-target-1':
        raise ValueError('complete explicit observation trial target required')
    if target['mode'] not in ('plain','pfblockerng'):raise ValueError('qualified policy mode required')
    if target['duration_seconds'] is not None and (type(target['duration_seconds']) is not int or not 15<=target['duration_seconds']<=86400):
        raise ValueError('explicit feed duration or until-stopped operation required')
    # Placeholder independent coordinator identity for pure input validation.
    coordinator=2 if target['resolver_pid']!=2 else 3
    context=validate_context({k:target[k] for k in context_keys}|{'format':'dnsalias-trial-worker-1','coordinator_pid':coordinator})
    if type(target['sources']) is not list or len(target['sources'])>20:raise ValueError('bounded explicit source specifications required')
    spec_fields={'name','path','uid','gid','modes','max_bytes'}
    if any(type(value) is not dict or set(value)!=spec_fields or type(value['modes']) not in (list,tuple) for value in target['sources']):
        raise ValueError('complete physical source metadata required')
    specs=[SourceSpec(**(value|{'modes':tuple(value['modes'])})) for value in target['sources']]
    expected=set(BASE_SOURCES)-{'observer_configuration'}
    if target['mode']=='pfblockerng':expected|=set(PFB_SOURCES)
    if {spec.name for spec in specs}!=expected or len(specs)!=len(expected):raise ValueError('complete exact physical source set required')
    if len({spec.path for spec in specs})!=len(specs):raise ValueError('distinct source paths required')
    if type(target['expected_sources']) is not dict or set(target['expected_sources'])!=expected:
        raise ValueError('complete independently inspected source hashes required')
    if any(type(value) is not str or not re.fullmatch('[a-f0-9]{64}',value) for value in target['expected_sources'].values()):
        raise ValueError('explicit expected SHA256 source identities required')
    root=Path(context['root']);selected={spec.name:spec for spec in specs}
    for label,name in COMPONENTS.items():
        if Path(selected[label].path)!=root/'dnsalias'/name:raise ValueError('source components must belong to installed package')
    if any(Path(selected[label].path).parent!=Path(context['control_directory']) for label in ('selected_hook','resolver_config')):
        raise ValueError('hook/config must belong to explicit resolver directory')
    if not selected['selected_hook'].path.endswith('.py'):raise ValueError('existing Python hook required')
    if type(target['excluded_addresses']) is not list or len(target['excluded_addresses'])>16:raise ValueError('bounded sinkhole list required')
    if any(type(value) is not str for value in target['excluded_addresses']):raise ValueError('literal sinkhole addresses required')
    for value in target['excluded_addresses']:ipaddress.ip_address(value)
    versions=target['versions'];version_keys={'pfsense','unbound','python'}|({'pfblockerng'} if target['mode']=='pfblockerng' else set())
    if (type(versions) is not dict or set(versions)!=version_keys or versions['unbound']!='1.26.1'
        or any(type(value) is not str or not re.fullmatch('[A-Za-z0-9_.+\\-]{1,80}',value) for value in versions.values())):
        raise ValueError('complete qualified installed version identities required')
    # Effective runtime settings are checked against the fresh native capture
    # and deployment descriptor before any hook mutation.
    return json.loads(json.dumps(target|{'probes':context['probes']},allow_nan=False))


def run(target,emit=None,*,feed=None,cancel_requested=None,supervised_health=False,runtime_audit_seconds=0):
    target=validate_target(target)
    if type(runtime_audit_seconds) is not int or runtime_audit_seconds not in (0,60):raise ValueError('qualified runtime audit cadence required')
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('qualified native root observation operator required')
    if emit is not None and not callable(emit):raise ValueError('optional bounded event callback required')
    if cancel_requested is not None and not callable(cancel_requested):raise ValueError('optional explicit cancellation source required')
    if type(supervised_health) is not bool or supervised_health and (feed is None or emit is None):raise ValueError('explicit supervised feed health sink required')
    if feed is not None:
        from .trialfeed import TrialFeed
        if type(feed) is not TrialFeed:raise ValueError('explicit qualified table feed required')
    import manage
    root,data=Path(target['root']),Path(target['data'])
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('operator must run from exact installed package')
    manage.verify(root,data)
    if manage.inspect_trial_directory(root,data) is not None:raise ValueError('existing trial requires inspection, never automatic reuse')
    specs=[SourceSpec(**(value|{'modes':tuple(value['modes'])})) for value in target['sources']]
    spec_by_name={spec.name:spec for spec in specs};ancestors=tuple(dict.fromkeys((0,target['control_uid'],*[spec.uid for spec in specs])))
    trial_id=uuid.uuid4().hex;endpoint=operation=store=service=sources=main_watch=audit_watch=probe=phase_reader=handoff=None
    persistent=feed is not None and feed.persistent
    guarded=feed is not None and feed.table_use=='supervised_block_trial'
    result={'format':'dnsalias-observation-trial-result-1','trial_id':trial_id,'enforcement_applied':None if guarded else False,
        'enforcement_scope':'external_block_trial_supervisor' if guarded else 'observation_only',
        'state':'preflight','error':None,'restoration_verified':False,'resources_released':False}
    try:
        versions=target['versions']
        actual={'pfsense':Path('/etc/version').read_text().strip(),'python':platform.python_version()}
        if target['mode']=='pfblockerng':
            package=subprocess.run(['/usr/local/sbin/pkg','query','%v','pfSense-pkg-pfBlockerNG'],capture_output=True,text=True,timeout=2)
            if package.returncode:raise ValueError('installed policy package identity unavailable')
            actual['pfblockerng']=package.stdout.strip()
        if type(versions) is not dict or any(versions.get(k)!=v for k,v in actual.items()):raise ValueError('inspected installed versions changed')
        main_watch=ProcessLifetimeWatch(target['resolver_pid']);boot=capture()
        credentials=load_credentials(target['control_directory'],expected_uid=target['control_uid'],expected_gid=target['control_gid'])
        control=RuntimeControl(credentials['context'],address='127.0.0.1',port=target['control_port'],
            server_certificate_sha256=credentials['server_certificate_sha256'])
        runtime=control.capture(main_watch)
        if versions.get('unbound')!=runtime['status']['version']:raise ValueError('inspected resolver version changed')
        settings=runtime['settings'];hook=Path(spec_by_name['selected_hook'].path)
        if settings['directory']!=target['control_directory'] or settings['python-script'] not in (hook.name,str(hook)):
            raise ValueError('running selected hook/directory does not match target')
        endpoint=TrialEndpoint(target['control_directory'],trial_id=trial_id,sender_uid=target['control_uid'],sender_gid=target['control_gid'])
        physical=endpoint.endpoint.path
        destination=str(Path('/')/physical.relative_to(settings['chroot'])) if settings['chroot'] else str(physical)
        fixed={'destination':destination,'policy_mode':target['mode'],'max_events_per_second':500,'burst':64}
        if persistent and feed.table_use=='dns_aliases':fixed['synchronous_mapping']=True
        with SourceAudit(specs,ancestor_uids=ancestors) as original:
            if original.hashes!=target['expected_sources']:raise ValueError('inspected physical sources changed')
            snapshot={'format':'dnsalias-deployment-2','mode':target['mode'],'versions':versions,'settings':settings,
                'sources':dict(original.hashes)|{'observer_configuration':configuration_fingerprint(**fixed)},
                'excluded_addresses':target['excluded_addresses']}
            expected_before=DeploymentFingerprint.from_snapshot(snapshot)
            bodies={key:Path(spec_by_name[key].path).read_text() for key in COMPONENTS}
            original_bytes=hook.read_bytes();original.audit()
            if feed is not None:
                spec,body,manifest=feed.prepare(target,trial_id,settings,bodies)
                specs=[spec if s.name=='observer_source' else s for s in specs]
                specs.extend(feed.extra_sources)
                bodies['observer_source']=body
                snapshot['sources']['observer_source']=manifest['observer_source_sha256']
                expected_before=DeploymentFingerprint.from_snapshot(snapshot)
            observer,_=render_observer(observer_source=bodies['observer_source'],extractor_source=bodies['extractor_source'],
                transport_source=bodies['transport_source'],profile_id=expected_before.identifier,**fixed)
            overlay,owned=render(original_bytes,observer,bodies['dispatcher_source'],expected_sha256=original.hashes['selected_hook'])
        intention=prepare(trial_id=trial_id,boot_id=boot['boot_id'],now=time.monotonic(),utc_now=time.time(),
            duration_seconds=target['duration_seconds'],hook=spec_by_name['selected_hook'],overlay=owned,
            config=spec_by_name['resolver_config'],config_sha256=snapshot['sources']['resolver_config'])
        manage.prepare_trial_directory(intention,root,data)
        context={k:target[k] for k in ('root','data','resolver_pid','control_directory','control_uid','control_gid','control_port','dns_port','probes')}
        context.update(format='dnsalias-trial-worker-1',coordinator_pid=os.getpid())
        operation=ObservationTrial(context,overlay=overlay,control=control,resolver_watch=main_watch,persistent=persistent)
        result['rollback_ready']=operation.arm()
        if emit:emit({'event':'rollback_ready','trial_id':trial_id,'worker':result['rollback_ready']['worker']})
        result['application']=operation.apply()
        sources=SourceAudit(specs,ancestor_uids=ancestors)
        if persistent:
            from .resolverreplacement import source_identity
            owned_source_identity=source_identity(sources)
        # Extra native assets are source-watched too. Their binary identity
        # and embedded loader bytes are already bound by the companion hash;
        # retain the exact public descriptor field set.
        snapshot['sources']={key:sources.hashes[key] for key in snapshot['sources'] if key!='observer_configuration'}|{'observer_configuration':configuration_fingerprint(**fixed)}
        expected=DeploymentFingerprint.from_snapshot(snapshot)
        if expected.identifier!=expected_before.identifier:raise ValueError('profile changed during controlled hook write')
        audit_watch=ProcessLifetimeWatch(target['resolver_pid'])
        producer=ProducerIdentity(target['resolver_pid'],target['control_uid'],boot['boot_id'],main_watch.lifetime_id)
        auditor=RuntimeDeploymentAudit(snapshot,producer,sources=sources,watch=audit_watch,control=control,
            observer_configuration=fixed,credential_directory=target['control_directory'],credential_uid=target['control_uid'],
            credential_gid=target['control_gid'],credential_id=credentials['credential_id'],runtime_interval_seconds=runtime_audit_seconds)
        if feed is None:store=EventStore(data/'events.sqlite',trial_id,busy_timeout_ms=20)
        if feed is not None:feed.before_reload(producer_pid=producer.pid,profile_id=expected.identifier,sources=sources)
        result['load']=operation.reload()
        startup=ReplyStartup(endpoint.endpoint,expected=expected,producer=producer,load_open=operation.load_open,persistent_start=persistent)
        service=(ReplyObservationService(startup,auditor=auditor,watch=main_watch,store=store) if feed is None
            else feed.start(startup,auditor=auditor,watch=main_watch,data=data,session=trial_id,producer_gid=target['control_gid']))
        probe=_EnrollmentProbe(target,control,operation.load_open,persistent_start=persistent);probe.start()
        from .hookphase import HookPhaseReader
        phase_reader=HookPhaseReader(operation.journal)
        def reader_handoff():
            if (not persistent or feed.confirmation_owner is None or startup.enrollment is None
                or not main_watch.alive()):return None
            proof=feed.confirmation_owner.poll_reload(main_watch,startup.enrollment)
            if proof is None:return None
            from .resolverhandoff import ResolverReloadHandoff
            return ResolverReloadHandoff(feed=feed,service=service,probe=probe,watch=main_watch,audit_watch=audit_watch,
                operation=operation,control=control,sources=sources,specs=specs,ancestors=ancestors,
                identity=owned_source_identity,snapshot=snapshot,credentials=credentials,target=target,
                boot_id=boot['boot_id'],probe_factory=_EnrollmentProbe,observer_configuration=fixed,proof=proof)
        next_owner_check=0;next_health=0;next_journal=0;phase=None;running_emitted=False;last_phase=None;observation_failure=None;stop_requested=False
        deadline=None if target['duration_seconds'] is None else intention['plan']['prepared_monotonic']+target['duration_seconds']+20
        while deadline is None or time.monotonic()<deadline:
            now=time.monotonic()
            if now>=next_owner_check:
                if not endpoint.healthy():raise ValueError('owned observation endpoint changed')
                next_owner_check=now+.25
            if now>=next_journal:
                phase=phase_reader.read_phase();next_journal=now+.1
            if phase!=last_phase:
                if emit:emit({'event':'trial_phase','phase':phase,'trial_id':trial_id})
                last_phase=phase
            if phase=='armed' and not stop_requested and cancel_requested is not None and cancel_requested() is True:
                operation.request_stop();stop_requested=True
                if emit:emit({'event':'observation_stop_requested','trial_id':trial_id})
            if phase=='armed' and not stop_requested:
                if persistent and handoff is None and not main_watch.alive() and main_watch.state=='exited':
                    from .resolverhandoff import ResolverHandoff
                    handoff=ResolverHandoff(feed=feed,service=service,probe=probe,watch=main_watch,audit_watch=audit_watch,
                        operation=operation,control=control,sources=sources,specs=specs,ancestors=ancestors,
                        identity=owned_source_identity,snapshot=snapshot,credentials=credentials,target=target,
                        boot_id=boot['boot_id'],probe_factory=_EnrollmentProbe,observer_configuration=fixed)
                    if emit:emit({'event':'resolver_waiting','trial_id':trial_id})
                if handoff is None:
                    handoff=reader_handoff()
                    if handoff is not None and emit:emit({'event':'resolver_waiting','trial_id':trial_id})
                if handoff is not None:
                    changed=handoff.step()
                    if changed is not None:
                        service,probe,main_watch,audit_watch,startup=(changed[k] for k in ('service','probe','watch','audit_watch','startup'))
                        sources,owned_source_identity=changed['sources'],changed['source_identity']
                        result.setdefault('resolver_handoffs',[]).append({k:changed[k] for k in ('pid','seconds')}|
                            {'kind':changed.get('kind','process_replacement')})
                        # Keep reporting bounded over an indefinitely running service.
                        result['resolver_handoffs']=result['resolver_handoffs'][-8:]
                        handoff.close();handoff=None
                        if emit:emit({'event':'observing','trial_id':trial_id})
                    else:
                        if operation.state!='following':
                            outcome=operation.poll()
                            if outcome is not None:raise ValueError('hook owner ended during resolver handoff')
                        time.sleep(.01)
                        continue
                if supervised_health and time.monotonic()>=next_health:
                    # Emit main-loop liveness BEFORE service.step can process
                    # the first positive startup reply. Its timestamp remains
                    # the freshness basis when a parent relays this pulse.
                    emit({'event':'feed_health','qualified':service.state=='running','monotonic':time.monotonic()})
                    next_health=time.monotonic()+.25
                service.step()
                if feed is not None:feed.collect()
                if startup.enrollment is not None:probe.observed.set()
                if service.state not in ('starting','running'):probe.close(wait_seconds=0)
                if (service.state not in ('starting','running')
                    and operation.journal.read()['checkpoint']['status']['phase']=='armed'):
                    observation_failure=observation_failure or service.reason or 'observation_ended'
                    # A graceful native restart removes the generation socket
                    # just before NOTE_EXIT. Preserve expiry while that bounded
                    # transition completes; never resume the retired receiver.
                    if persistent and service.reason in ('reply_endpoint_changed','producer_lifetime_ended'):
                        # Original hook deinit may still be running after our
                        # endpoint closes. Native shutdown can take seconds;
                        # keep expiring leases until NOTE_EXIT is confirmed.
                        # This never qualifies a live/foreign replacement.
                        until=time.monotonic()+6
                        while main_watch.alive() and time.monotonic()<until:
                            feed.expire()
                            if cancel_requested is not None and cancel_requested() is True:break
                            handoff=reader_handoff()
                            if handoff is not None:
                                if emit:emit({'event':'resolver_waiting','trial_id':trial_id})
                                break
                            time.sleep(.01)
                        if handoff is not None or (not main_watch.alive() and main_watch.state=='exited'):
                            observation_failure=None
                            continue
                    if target['duration_seconds'] is None and not stop_requested:
                        operation.request_stop();stop_requested=True
                if service.state=='running' and not running_emitted:
                    running_emitted=True
                    if emit:emit({'event':'observing','trial_id':trial_id})
            else:service.close(wait_seconds=0)
            outcome=operation.poll()
            if outcome is not None:
                result['rollback']=outcome;result['restoration_verified']=outcome['journal_phase']=='complete'
                result['state']='complete' if result['restoration_verified'] and running_emitted and observation_failure is None else 'unqualified'
                if stop_requested and result['restoration_verified']:result['state']='cancelled'
                break
            if feed is None or phase!='armed' or stop_requested or service.state not in ('starting','running'):
                # An unconsumed datagram can remain readable during shutdown;
                # do not spin on a socket the closed service will not drain.
                time.sleep(.01)
            else:
                # DNS datagrams wake select immediately. Persistent owners can
                # sleep longer while idle without delaying a known lease expiry.
                # A readable DNS socket wakes immediately. The quarter-second
                # idle cap also aligns with endpoint/health checks; an earlier
                # lease deadline below always wins.
                wait=.25 if target['duration_seconds'] is None else .01
                expiry=(feed.owner.next_expiry_attempt() if feed.owner is not None
                        else feed.writer.status()['next_deadline'])
                if expiry is not None:wait=min(wait,max(.001,expiry-time.monotonic()))
                readers=[endpoint.endpoint.socket]
                if feed.confirmation_owner is not None and feed.confirmation_owner.retirement is not None:
                    readers.append(feed.confirmation_owner.retirement.socket)
                select.select(readers,[],[],wait)
        else:raise TimeoutError('bounded observation trial completion deadline')
        result['observation_started']=running_emitted;result['observation_failure']=observation_failure
        result['stop_requested']=stop_requested
        result['observation']=service.status()
        if store is not None:result['storage']=store.storage()
    except Exception as exc:
        result['state']='uncertain';result['error']=type(exc).__name__
        if isinstance(exc,SourceChanged):
            result['source_error']=str(exc)[:240]
        cause=exc
        for unused in range(4):
            if isinstance(cause,OSError) and type(cause.errno) is int:
                result['error_errno']=cause.errno;break
            cause=cause.__cause__
            if cause is None:break
        result['error_at']=[{'function':frame.name,'line':frame.lineno}
            for frame in traceback.extract_tb(exc.__traceback__)[-3:]]
    finally:
        if handoff is not None:
            result['resolver_handoff']=handoff.status()
            service,probe=handoff.service,handoff.probe
        probe_released=True if probe is None else probe.close()
        if probe is not None:result['startup_probe']=probe.status()
        released=True
        if service is not None:
            released=service.close(wait_seconds=.1);until=time.monotonic()+1.2
            while not released and time.monotonic()<until:released=service.close(wait_seconds=.1)
            result['final_observation']=service.status()
        released=released and probe_released
        # The independent worker retains its original deadline on every error.
        # An unfinished trial's package/data must remain available for it.
        if phase_reader is not None:phase_reader.close()
        if operation is not None:operation.close()
        if handoff is not None:released=handoff.close() and released
        if released:
            if store is not None:store.close()
            if sources is not None:sources.close()
            if audit_watch is not None:audit_watch.close()
            if endpoint is not None:result['endpoint_cleanup']=endpoint.close()
        if feed is not None:
            result['feed']=feed.finish(restoration_verified=result['restoration_verified'],resources_released=released)
            cleanup=result['feed']['cleanup']
            if not cleanup['owned_resources_removed'] or not cleanup['telemetry_closed'] or cleanup['error']:
                result['state']='unqualified'
            released=released and cleanup['telemetry_closed']
        if main_watch is not None:main_watch.close()
        result['resources_released']=released
    return result
