"""Explicit independent rollback process for an owned observation trial.

Never started by installation, the GUI, boot or import. The launcher provides a
bounded context through a private pipe, prepares the owned journal, and waits
for this process's durable ready acknowledgement before applying any overlay.
This worker only restores the exact original prefix and issues the fixed TLS
reload. It cannot apply an overlay, change rules or adopt a changed resolver.
Selected DNS checks compare behavior, not loaded-code identity or all policy.
"""
import json
import os
from pathlib import Path
import select
import sys
import time

from .dnscheck import _question,query
from .sourceaudit import SourceAudit,SourceSpec,_path


def await_control(control,resolver,*,budget_seconds=8,replacement_reload=False,persistent_start=False):
    """Read-only readiness wait; never repeat a reload or accept another PID."""
    from .runtimecontrol import RuntimeControlError,status_value
    if type(replacement_reload) is not bool:raise ValueError('explicit replacement reload mode required')
    if type(persistent_start) is not bool or persistent_start and replacement_reload:raise ValueError('explicit initial service readiness mode required')
    limit=8
    if replacement_reload or persistent_start:
        from .replystartup import ReplyStartup
        limit=ReplyStartup.INITIAL_SERVICE_SECONDS if persistent_start else ReplyStartup.REPLACEMENT_SECONDS
    if type(budget_seconds) not in (int,float) or not 0<budget_seconds<=limit:raise ValueError('bounded readiness budget required')
    started=time.monotonic();deadline=started+budget_seconds;attempts=0
    while resolver.alive():
        remaining=deadline-time.monotonic()
        if remaining<=0:break
        attempts+=1
        try:
            status=status_value(control._read(None,time.monotonic()+min(.2,remaining)))
        except RuntimeControlError as exc:
            # Pin, TLS verification, parsing and other errors are permanent.
            if not isinstance(exc.__cause__,(TimeoutError,ConnectionRefusedError,ConnectionResetError)):raise
        else:
            if status['pid']!=resolver.pid or not resolver.alive():raise ValueError('resolver identity changed during readiness')
            if time.monotonic()>deadline:break
            return {'ready':True,'read_attempts':attempts,'elapsed_seconds':time.monotonic()-started}
        time.sleep(min(.05,max(0,deadline-time.monotonic())))
    raise TimeoutError('enrolled resolver readiness not established within bound')


def match_baseline(probes,baseline,*,port,resolver,budget_seconds=None,persistent=False):
    """Confirm two matching DNS rounds after one reload of the enrolled resolver."""
    if type(persistent) is not bool:raise ValueError('explicit persistent mode required')
    # The persistent service can reload a large resolver configuration on Stop.
    # This clock is only used by the independent rollback worker.
    limit=12 if persistent else 8
    if budget_seconds is None:budget_seconds=limit
    if type(budget_seconds) not in (int,float) or not 0<budget_seconds<=limit:raise ValueError('bounded DNS verification budget required')
    if not 1<=len(probes)<=4 or len(probes)!=len(baseline):raise ValueError('bounded matching probe baseline required')
    started=time.monotonic();deadline=started+budget_seconds;rounds=0;attempts=0;verified=[]
    transport={'timeout':0,'refused':0,'reset':0}
    while resolver.alive() and time.monotonic()<deadline:
        answers=[];attempts+=1
        try:
            for probe in probes:
                remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('DNS verification deadline')
                answers.append(query(probe['name'],kind=probe['kind'],port=port,timeout_seconds=min(.2,remaining)))
        except (TimeoutError,ConnectionRefusedError,ConnectionResetError) as exc:
            kind='timeout' if isinstance(exc,TimeoutError) else 'refused' if isinstance(exc,ConnectionRefusedError) else 'reset'
            transport[kind]+=1;rounds=0;verified.clear()
        else:
            if answers!=baseline:
                return {'matched':False,'reason':'answer_changed','verified_probes':[],
                    'read_attempts':attempts,'transport_failures':transport,'budget_seconds':budget_seconds,'elapsed_seconds':time.monotonic()-started}
            rounds+=1;verified.extend(probe['name'] for probe in probes)
            if rounds==2 and resolver.alive() and time.monotonic()<=deadline:
                return {'matched':True,'reason':None,'verified_probes':verified,
                    'read_attempts':attempts,'transport_failures':transport,'budget_seconds':budget_seconds,'elapsed_seconds':time.monotonic()-started}
        time.sleep(min(.05,max(0,deadline-time.monotonic())))
    return {'matched':False,'reason':'deadline_or_resolver_ended','verified_probes':[],
            'end_condition':'resolver_ended' if not resolver.alive() else 'deadline',
        'read_attempts':attempts,'transport_failures':transport,'budget_seconds':budget_seconds,'elapsed_seconds':time.monotonic()-started}


def validate_context(value):
    fields={'format','root','data','coordinator_pid','resolver_pid','control_directory',
        'control_uid','control_gid','control_port','dns_port','probes'}
    if type(value) is not dict or set(value)!=fields or value['format']!='dnsalias-trial-worker-1':
        raise ValueError('complete explicit trial worker context required')
    for key in ('root','data','control_directory'):_path(value[key])
    if len({value[key] for key in ('root','data','control_directory')})!=3:
        raise ValueError('distinct package, data and resolver directories required')
    for key in ('coordinator_pid','resolver_pid'):
        if type(value[key]) is not int or not 1<value[key]<2**31:raise ValueError('explicit native process required')
    if value['coordinator_pid']==value['resolver_pid']:raise ValueError('independent coordinator and resolver required')
    for key in ('control_uid','control_gid'):
        if type(value[key]) is not int or not 0<=value[key]<2**32:raise ValueError('explicit credential ownership required')
    for key in ('control_port','dns_port'):
        if type(value[key]) is not int or not 1<=value[key]<=65535:raise ValueError('explicit loopback service ports required')
    if value['control_port']==value['dns_port']:raise ValueError('distinct service ports required')
    probes=value['probes']
    if type(probes) is not list or not 1<=len(probes)<=4:raise ValueError('one to four explicit DNS probes required')
    canonical=[]
    for probe in probes:
        if type(probe) is not dict or set(probe)!={'name','kind'}:raise ValueError('explicit DNS name and type required')
        name,_=_question(probe['name'],probe['kind']);canonical.append({'name':name,'kind':probe['kind']})
    if len({(p['name'],p['kind']) for p in canonical})!=len(canonical):raise ValueError('distinct DNS probes required')
    return json.loads(json.dumps(value|{'probes':canonical},allow_nan=False))


def read_context(fd):
    """One bounded pipe record; never wait indefinitely for a missing newline."""
    deadline=time.monotonic()+2;raw=bytearray()
    while len(raw)<=8192:
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([fd],[],[],remaining)[0]:raise ValueError('context pipe deadline')
        chunk=os.read(fd,8193-len(raw))
        if not chunk:raise ValueError('incomplete context pipe record')
        raw.extend(chunk)
        if b'\n' in raw:
            if raw[-1:]!=b'\n' or b'\n' in raw[:-1] or len(raw)>8192:raise ValueError('one bounded context record required')
            return validate_context(json.loads(raw))
    raise ValueError('context exceeds cap')


class StopPipe:
    """One fixed private-pipe command, polled without waiting or unbounded reads.

    EOF and malformed input disable the command path; the independently fixed
    deadline and coordinator process watch remain authoritative. No pipe data
    can extend that deadline, select a target or trigger a new operation.
    """
    def __init__(self,fd):
        self.fd=fd;self.pending=bytearray();self.state='waiting'

    def poll(self):
        if self.state!='waiting':return self.state=='stop'
        try:
            if not select.select([self.fd],[],[],0)[0]:return False
            chunk=os.read(self.fd,6-len(self.pending))
            if not chunk:self.state='closed';return False
            self.pending.extend(chunk)
            if bytes(self.pending)==b'stop\n':self.state='stop';return True
            if not b'stop\n'.startswith(self.pending):self.state='invalid'
        except (OSError,ValueError):self.state='unavailable'
        return False


class PersistentPipe:
    """Two fixed pipe commands; no supplied PID, path or configuration."""
    def __init__(self,fd):self.fd=fd;self.pending=b'';self.state='waiting';self.follow=False

    def poll(self):
        if self.state!='waiting':return self.state=='stop'
        try:
            if not select.select([self.fd],[],[],0)[0]:return False
            chunk=os.read(self.fd,16-len(self.pending))
            if not chunk:self.state='closed';return False
            self.pending+=chunk
            if b'\n' in self.pending:
                line,rest=self.pending.split(b'\n',1)
                if rest or line not in (b'stop',b'follow'):self.state='invalid';return False
                self.pending=b''
                if line==b'stop':self.state='stop';return True
                if self.follow:self.state='invalid';return False
                self.follow=True
            elif len(self.pending)>=16:self.state='invalid'
        except (OSError,ValueError):self.state='unavailable'
        return False

    def take_follow(self):
        value,self.follow=self.follow,False;return value


def run(context,emit,*,stop_requested=None,follow_requested=None):
    """Run in a separate process; writes only the owned trial and exact hook."""
    context=validate_context(context)
    if stop_requested is not None and not callable(stop_requested):raise ValueError('optional private stop source required')
    if follow_requested is not None and not callable(follow_requested):raise ValueError('optional fixed follow source required')
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('qualified native root worker required')
    if os.getpid() in (context['coordinator_pid'],context['resolver_pid']):raise ValueError('independent worker process required')
    import manage
    from .bootidentity import capture
    from .hookrollback import HookRollbackController
    from .hooktrial import HookTrialFile
    from .processwatch import ProcessLifetimeWatch
    from .reloadrequest import ReloadRequest
    from .runtimecontrol import RuntimeControl,load_credentials,status_value

    root,data=Path(context['root']),Path(context['data'])
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('worker must run from the exact installed package')
    manage.verify(root,data)
    owned=manage.inspect_trial_directory(root,data)
    if owned is None or owned['phase']!='prepared' or owned['pending_file']:raise ValueError('owned prepared journal required')
    with HookTrialFile(data/manage.TRIAL_DIRECTORY,expected_uid=0) as journal:
        plan=journal.read()['checkpoint']['plan']
        directory=Path(context['control_directory'])
        if any(Path(plan[key]['path']).parent!=directory for key in ('hook','config')):
            raise ValueError('hook and configuration must belong to the explicit resolver directory')
        specs=[SourceSpec(**(plan[key]|{'modes':tuple(plan[key]['modes'])})) for key in ('hook','config')]
        ancestors=tuple(dict.fromkeys((0,context['control_uid'],*[spec.uid for spec in specs])))
        with ProcessLifetimeWatch(context['coordinator_pid']) as coordinator,ProcessLifetimeWatch(context['resolver_pid']) as resolver:
            extra_watches=[]
            boot=capture()
            if boot['boot_id']!=plan['boot_id']:raise ValueError('prepared boot changed')
            credentials=load_credentials(str(directory),expected_uid=context['control_uid'],expected_gid=context['control_gid'])
            control=RuntimeControl(credentials['context'],address='127.0.0.1',port=context['control_port'],
                server_certificate_sha256=credentials['server_certificate_sha256'])
            def credential_identity():
                if not resolver.alive():raise ValueError('enrolled resolver lifetime ended')
                fresh=load_credentials(str(directory),expected_uid=context['control_uid'],expected_gid=context['control_gid'])
                if fresh['credential_id']!=credentials['credential_id']:raise ValueError('control credentials changed')
            def identity():
                credential_identity()
                await_control(control,resolver,budget_seconds=3)
            def inspect(current):
                with SourceAudit(specs,ancestor_uids=ancestors) as audit:
                    hashes=audit.audit()['sources']
                    return {'hook_sha256':hashes['selected_hook'],'config_sha256':hashes['resolver_config']}
            def restore(current):
                # Restoration of owned disk bytes must not wait for an
                # interrupted coordinator's still-running policy reload.
                credential_identity()
                with SourceAudit(specs,ancestor_uids=ancestors) as audit:
                    if audit.hashes['resolver_config']!=current['config_sha256']:raise ValueError('resolver configuration changed')
                    from .plainsetup import exchange_owned
                    exchange_owned(data,audit,current['overlay'])
            reloads=[];verified=[];readiness=[];verification=[]
            def reload(current):
                credential_identity();readiness.append(await_control(control,resolver))
                credential_identity();reloads.append(ReloadRequest(control,resolver).send())
            def answers():
                return [query(p['name'],kind=p['kind'],port=context['dns_port'],timeout_seconds=.2) for p in context['probes']]
            identity();initial_runtime=control.capture(resolver) if follow_requested is not None else None
            baseline=answers()
            if any(reply['rcode'] not in (0,3) for reply in baseline) or answers()!=baseline:
                raise ValueError('stable successful or negative baseline DNS behavior required')
            identity()
            def verify(current):
                outcome=match_baseline(context['probes'],baseline,port=context['dns_port'],resolver=resolver,
                    persistent=follow_requested is not None and plan['duration_seconds'] is None)
                verification.append(outcome)
                if not outcome['matched']:return False
                identity();verified.extend(outcome['verified_probes']);return True
            def qualify_replacement(candidate):
                fresh=load_credentials(str(directory),expected_uid=context['control_uid'],expected_gid=context['control_gid'])
                if fresh['credential_id']!=credentials['credential_id']:raise ValueError('control credentials changed')
                current=control.capture(candidate)
                if current['settings']!=initial_runtime['settings'] or current['status']['version']!=initial_runtime['status']['version']:
                    raise ValueError('replacement runtime changed')
                return candidate.alive() and coordinator.alive()
            controller_type=HookRollbackController;options={}
            if follow_requested is not None:
                from .persistenthook import PersistentHookController
                controller_type=PersistentHookController;options={'qualify_resolver':qualify_replacement}
            controller=controller_type(journal,boot_id=boot['boot_id'],coordinator_watch=coordinator,
                resolver_watch=resolver,inspect=inspect,restore=restore,reload=reload,verify_loaded=verify,**options)
            emit(controller.arm())
            try:
                while controller.state=='armed':
                    controller.step(stop_requested=stop_requested() if stop_requested is not None else False)
                    if controller.state=='armed' and follow_requested is not None and follow_requested():
                        # The pipe cannot choose the replacement. Independently
                        # discover the native TLS server PID and qualify it.
                        candidate=None
                        try:
                            pid=status_value(control._read(None,time.monotonic()+.5))['pid']
                            candidate=ProcessLifetimeWatch(pid);extra_watches.append(candidate)
                            followed=controller.follow_resolver(candidate)
                            resolver=candidate
                            # Only the current replacement watch is retained.
                            # Earlier confirmed-exit watches cannot accumulate
                            # across an indefinitely running service lifetime.
                            for retired in tuple(extra_watches):
                                if retired is not candidate:retired.close();extra_watches.remove(retired)
                            emit(followed)
                        except Exception:
                            # No automatic follow/reload retry after refusal or
                            # an uncertain journal write. Preserve all evidence.
                            if controller.state=='armed':controller._uncertain('replacement_discovery_failed')
                            break
                    time.sleep(.1)
            finally:
                for value in extra_watches:value.close()
            result={'controller':controller.status(),'journal_phase':journal.read()['checkpoint']['status']['phase'],
                'restored_policy_answers':verified,'reload_requests':reloads,'independent_process':True,
                'installed_worker':True,'baseline_probe_count':len(baseline),'enforcement_applied':False,
                'pre_reload_readiness':readiness,'dns_verification':verification,
                'verification_scope':'Selected loopback DNS behavior; not loaded-code identity or complete policy coverage'}
            emit(result)
            return 0 if controller.state=='complete' else 1


def main():
    if sys.argv[1:] not in (['--run-prepared-observation-trial'],['--run-persistent-observation-hook']):
        raise ValueError('explicit prepared observation trial invocation required')
    # No context contents, private paths, credentials or exception text on error.
    fd=sys.stdin.fileno();context=read_context(fd)
    persistent=sys.argv[1:] == ['--run-persistent-observation-hook']
    stop=PersistentPipe(fd) if persistent else StopPipe(fd)
    return run(context,lambda value:print(json.dumps(value),flush=True),stop_requested=stop.poll,
        follow_requested=stop.take_follow if persistent else None)


if __name__=='__main__':
    try:result=main()
    except Exception as exc:
        print(json.dumps({'worker_failed':type(exc).__name__,'automatic_retry':False}),flush=True);result=1
    raise SystemExit(result)
