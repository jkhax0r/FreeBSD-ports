"""Persistent multi-alias DNS feed. Firewall rules are ordinary native rules.

Configuration owns names/tables; the running trusted reply ledger owns IPs.
No session timer, periodic DNS resolving, saved IP list or automatic rules.
"""
import argparse
from dataclasses import asdict
import fcntl
import json
import os
from pathlib import Path
import platform
import pwd
import signal
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from .collector import write_json
from .indexedproofs import IndexedProofLedger
from .leases import Policy
from .membershipgate import MembershipGate,create as create_gate
from .pfapi import NativePFTables
from .pfwriter import LeaseTableWriter
from .processwatch import ProcessLifetimeWatch
from .reloadlock import SharedReloadLock,ReloadBusy
from .runtimecontrol import RuntimeControl,load_credentials,status_value
from .sourceaudit import SourceAudit,SourceSpec
from .trialfeed import TrialFeed
from .trialservice import COMPONENTS,run as run_feed,validate_target
from .lifecycle import current,guarded,Lifetime
from .policyrefresh import PolicyRefresh

ROOT=Path('/usr/local/libexec/dnsalias')
DATA=Path('/var/db/dnsalias')
RUNTIME=Path('/var/run/dnsalias-aliases')
CONFIG=Path('/cf/conf/config.xml')
# Saving many names can take longer than a single DNS reply. Keep the
# configuration transaction bounded within the independent watch interval.
POLICY_APPLY_SECONDS = 1.0


def config_identity():
    value=CONFIG.stat()
    return value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns


def read_saved_for_refresh():
    # The background reader retains its own source lifetime, including during
    # Stop. A slow PHP process cannot race source replacement or uninstallation.
    with Lifetime(ROOT,DATA):return saved(ROOT)


def saved(root=ROOT):
    p=subprocess.run(['/usr/local/bin/php',str(root/'native/policies.php')],capture_output=True,text=True,timeout=2)
    if p.returncode or len(p.stdout)>262144+128:raise ValueError('saved alias configuration unavailable: '+p.stderr[:160])
    value=json.loads(p.stdout)
    if value.get('format')!='dnsalias-saved-aliases-1':raise ValueError('saved aliases format changed')
    # Use the shared canonical Python name validator as a second boundary.
    policies=value['policies']
    if not isinstance(policies,list) or len(policies)>127:raise ValueError('alias count exceeded')
    for p in policies:
        if (set(p)!={'name','names','enabled'} or type(p['enabled']) is not bool
            or list(Policy(p['name'],tuple(p['names'])).patterns)!=p['names']):raise ValueError('invalid saved policy')
    if len({p['name'] for p in policies})!=len(policies):raise ValueError('duplicate alias')
    return policies


def target(root=ROOT,data=DATA):
    """Inspect the actual selected Unbound hook and sources at every start."""
    identity=pwd.getpwnam('unbound');directory=Path('/var/unbound')
    credentials=load_credentials(str(directory),expected_uid=identity.pw_uid,expected_gid=identity.pw_gid)
    control=RuntimeControl(credentials['context'],address='127.0.0.1',port=953,
        server_certificate_sha256=credentials['server_certificate_sha256'])
    pid=status_value(control._read(None,time.monotonic()+.5))['pid']
    with ProcessLifetimeWatch(pid) as watch:runtime=control.capture(watch)
    settings=runtime['settings'];selected=settings['python-script']
    hook=Path(selected) if selected.startswith('/') else directory/selected
    if not selected or hook.parent!=directory:raise ValueError('an existing selected Python hook in /var/unbound is required')
    mode='pfblockerng' if hook.name=='pfb_unbound.py' else 'plain'
    if mode=='plain':
        from .plainlibrary import ready as library_ready
        library_ready(data)
    paths={'resolver_binary':'/usr/local/sbin/unbound','resolver_config':str(directory/'unbound.conf'),
        'selected_hook':str(hook),'services_source':'/etc/inc/services.inc','unbound_source':'/etc/inc/unbound.inc'}
    paths.update({k:str(root/'dnsalias'/v) for k,v in COMPONENTS.items()})
    if mode=='pfblockerng':paths.update(policy_vendor_hook='/usr/local/pkg/pfblockerng/pfb_unbound.py',
        policy_runtime_include=str(directory/'pfb_unbound_include.inc'),policy_vendor_include='/usr/local/pkg/pfblockerng/pfb_unbound_include.inc',
        policy_config=str(directory/'pfb_unbound.ini'),policy_package_source='/usr/local/pkg/pfblockerng/pfblockerng.inc')
    specs=[]
    for name,path in paths.items():
        info=Path(path).lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,identity.pw_uid):raise ValueError('untrusted resolver source')
        specs.append(SourceSpec(name,path,info.st_uid,info.st_gid,(stat.S_IMODE(info.st_mode),),8388608 if name=='resolver_binary' else 1048576))
    with SourceAudit(specs,ancestor_uids=(0,identity.pw_uid)) as audit:hashes=dict(audit.hashes)
    versions={'pfsense':Path('/etc/version').read_text().strip(),'unbound':runtime['status']['version'],'python':platform.python_version()}
    if mode=='pfblockerng':
        if hashes['selected_hook']!=hashes['policy_vendor_hook']:raise ValueError('selected hook is already modified; inspect before start')
        versions['pfblockerng']=subprocess.run(['/usr/local/sbin/pkg','query','%v','pfSense-pkg-pfBlockerNG'],capture_output=True,text=True,check=True,timeout=2).stdout.strip()
    config=ET.parse('/cf/conf/config.xml').getroot()
    probe=config.findtext('system/hostname')+'.'+config.findtext('system/domain')
    return validate_target({'format':'dnsalias-observation-trial-target-1','root':str(root),'data':str(data),
        'resolver_pid':pid,'control_directory':str(directory),'control_uid':identity.pw_uid,'control_gid':identity.pw_gid,
        'control_port':953,'dns_port':53,'probes':[{'name':probe,'kind':1}],
        'sources':[asdict(s) for s in specs],'expected_sources':hashes,'versions':versions,'mode':mode,
        'excluded_addresses':[],'duration_seconds':None})


def process():
    try:pid=int((DATA/'alias-service.pid').read_text())
    except FileNotFoundError:return None
    if pid<=1:raise ValueError('invalid alias service PID')
    p=subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','command='],capture_output=True,text=True,timeout=1)
    if not p.stdout.strip():return None
    if p.stdout.strip() not in ('/usr/local/bin/python3.11 -B -m dnsalias.aliasservice run',f'/usr/local/bin/python3.11 -B {ROOT}/dnsalias/lifecycle.py alias run'):raise ValueError('alias service PID was reused')
    return pid


def status():
    try:value=json.loads((DATA/'alias-status.json').read_text())
    except FileNotFoundError:value={'state':'stopped','tables':{}}
    pid=process()
    value['pid']=pid
    # Cached ledger counts are useful history, but only this request's PF read
    # establishes current membership. Never reuse a prior observation marker.
    value['membership_observed_utc']=None
    value['table_counts']={}
    value['tables']={}
    value.pop('membership_error',None)
    try:
        from .serviceboot import registration
        value['boot_enabled']=registration(ROOT,DATA) is not None
    except Exception as exc:value['boot_error']=type(exc).__name__
    if pid is None and value.get('state') in ('starting','running'):value['state']='stopped unexpectedly'
    if value.get('state') in ('running','failed','stopped unexpectedly'):
        try:
            names=tuple('da_'+p['name'] for p in saved(ROOT))
            if names:
                with NativePFTables('',names) as observed:tables=observed.snapshot()
                value['table_counts']={n:len(v) for n,v in tables.items()}
                value['tables']={n:sorted(v)[:100] for n,v in tables.items()}
                value['membership_observed_utc']=time.time()
        except Exception as exc:value['membership_error']=type(exc).__name__
    return value


@guarded(control=True,targets=lambda:(ROOT,DATA))
def start():
    import manage
    manage.verify(ROOT,DATA)
    if process() is not None:return {'already_running':True}
    if not saved(ROOT):raise ValueError('create a DNS alias first')
    if manage.inspect_trial_directory(ROOT,DATA) is not None:
        from .serviceboot import reconcile
        reconcile(ROOT,DATA)
    subprocess.run(['/usr/sbin/daemon','-f','-p',str(DATA/'alias-service.pid'),'/usr/local/bin/python3.11','-B',str(ROOT/'dnsalias/lifecycle.py'),'alias','run'],cwd=ROOT,check=True,timeout=3)
    return {'start_dispatched':True,'duration':'until stopped'}


@guarded(control=True,targets=lambda:(ROOT,DATA))
def stop(*,wait=False):
    if type(wait) is not bool:raise ValueError('explicit service stop wait required')
    pid=process()
    if pid is None:return {'stop_requested':False,**({'stopped':True} if wait else {})}
    if not wait:
        os.kill(pid,signal.SIGTERM);return {'stop_requested':True}
    # Enroll before signalling, then recheck the exact owned command. Observe
    # this lifetime's exit instead of querying a zombie or a recycled PID.
    with ProcessLifetimeWatch(pid) as watch:
        if process()!=pid:raise ValueError('alias service changed before stop')
        if not watch.alive():raise ValueError('alias service lifetime ended before stop')
        os.kill(pid,signal.SIGTERM);until=time.monotonic()+15
        while watch.alive():
            if time.monotonic()>=until:raise RuntimeError('alias feed is still stopping; retain package files')
            time.sleep(.05)
        if watch.state!='exited':raise ValueError('alias service exit could not be qualified')
    return {'stop_requested':True,'stopped':True}


def _table_create(names):
    # Only saved, checked namespace identities reach this call. A table can be
    # referenced by ordinary pass/block rules. No main rule reload is needed.
    with SharedReloadLock('/tmp/filter.lock'):
        for name in names:
            result=subprocess.run(['/sbin/pfctl','-t',name,'-T','replace','-f','/dev/null'],capture_output=True,text=True,timeout=1)
            if result.returncode:raise RuntimeError('cannot initialize '+name)


@guarded(targets=lambda:(ROOT,DATA))
def run(*,confirmation_reuse=True,confirmation_refresh=True):
    # The release path includes source/filter notices and fresh enrollment.
    # Explicit False/False remains available for matched private diagnostics.
    if type(confirmation_reuse) is not bool:raise ValueError('explicit confirmation test mode required')
    if type(confirmation_refresh) is not bool or (confirmation_refresh and not confirmation_reuse):
        raise ValueError('refresh requires explicit confirmation test mode')
    import manage
    from .triallaunch import _resource_limits
    _resource_limits(confirmation_refresh=confirmation_refresh);manage.verify(ROOT,DATA)
    lock=os.open(DATA/'alias-service.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    stopping=False
    def stopped(*unused):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stopped);signal.signal(signal.SIGINT,stopped)
    state={'state':'starting','started_utc':time.time(),'updated_utc':time.time(),'tables':{},'error':None,'duration':'until stopped'}
    write_json(DATA/'alias-status.json',state)
    native=writer=member=watcher=confirmation=refresh=None;descriptor=None;result=None;confirmation_descriptor=None
    try:
        last_config=config_identity()
        configuration=saved(ROOT)
        configured=[Policy(p['name'],tuple(p['names'])) for p in configuration]
        active=[policy for policy,entry in zip(configured,configuration) if entry['enabled']]
        if not configuration:raise ValueError('create an alias before starting the feed')
        inspected=target(ROOT,DATA)
        names=tuple('da_'+p['name'] for p in configuration)
        _table_create(names)
        RUNTIME.mkdir(mode=0o700)
        descriptor=create_gate(RUNTIME,uid=0,gid=0);member=MembershipGate(descriptor)
        watcher=subprocess.Popen([sys.executable,'-B','-m','dnsalias.aliaswatch'],cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        state.update(membership_gate=descriptor,guard_pid=watcher.pid)
        write_json(DATA/'alias-status.json',state)
        def protect(names):
            from .blockservice import _Reader
            request={'parent':os.getpid(),'gate':descriptor,'tables':names}
            if confirmation_descriptor is not None:request['confirmation']=confirmation_descriptor
            watcher.stdin.write((json.dumps(request)+'\n').encode());watcher.stdin.flush()
            reader=_Reader(watcher.stdout);until=time.monotonic()+2
            while time.monotonic()<until:
                values=reader.take()
                if values:
                    if values!=[{'protected':list(names)}]:raise RuntimeError('unexpected membership watch response')
                    return
                if watcher.poll() is not None:break
                time.sleep(.01)
            raise RuntimeError('membership watch did not acknowledge owned tables')
        protect(names)
        if confirmation_reuse:
            from .confirmationowner import ConfirmationOwner
            credentials=load_credentials(inspected['control_directory'],expected_uid=inspected['control_uid'],expected_gid=inspected['control_gid'])
            control=RuntimeControl(credentials['context'],address='127.0.0.1',port=inspected['control_port'],
                server_certificate_sha256=credentials['server_certificate_sha256'])
            with ProcessLifetimeWatch(inspected['resolver_pid']) as watch:settings=control.capture(watch)['settings']
            confirmation=ConfirmationOwner.create(ROOT,inspected['control_directory'],settings,
                resolver_uid=inspected['control_uid'],resolver_gid=inspected['control_gid'],refresh=confirmation_refresh,same_pid_reload=True)
            confirmation_descriptor=confirmation.cleanup_descriptor()
            protect(names)
            confirmation.acknowledge_cleanup(watcher.pid)
        native=NativePFTables('',names,writable=True);native.enroll({n:set() for n in names})
        # Enroll all configured tables; disabled aliases are removed immediately
        # below, before processing the first DNS callback.
        ledger=IndexedProofLedger(configured,
            **({'before_commit':confirmation.authority.before_commit} if confirmation is not None else {}))
        writer=LeaseTableWriter(ledger,native,reload_lock_path='/tmp/filter.lock',membership_gate=member,allow_late_completion=True,
            confirmation=confirmation.authority if confirmation is not None else None)
        writer.replace_policies(active,deadline=time.monotonic()+POLICY_APPLY_SECONDS)
        feed=TrialFeed(writer,table_use='dns_aliases',persistent=True,confirmation_owner=confirmation)
        next_config=next_status=next_pulse=0
        refresh=PolicyRefresh(read_saved_for_refresh,config_identity)
        seed=None;shutdown_sent=False
        def event(value):
            nonlocal seed
            if value.get('event')=='resolver_waiting':
                state['state']='waiting_for_resolver'
                if seed is not None:seed.close(cancelled=True);seed=None
            if value.get('event')=='observing':
                from .seedqueries import SeedQueries
                state['state']='running'
                exact=tuple(dict.fromkeys(n for p in configuration if p['enabled'] for n in p['names'] if not n.startswith('*.')))
                if exact:seed=SeedQueries(exact[:8],inspected['dns_port'],cancel_requested=lambda:stopping)
        def control():
            nonlocal last_config,next_config,next_status,next_pulse,configuration,shutdown_sent,seed,stopping
            now=time.monotonic()
            if stopping:
                if not shutdown_sent:
                    state.update(state='stopping',updated_utc=time.time());write_json(DATA/'alias-status.json',state)
                    watcher.stdin.write(b'stopping\n');watcher.stdin.flush();shutdown_sent=True
                return True
            if now>=next_pulse:
                watcher.stdin.write(b'pulse\n');watcher.stdin.flush();next_pulse=now+.5
                if not member.available() or watcher.poll() is not None:raise RuntimeError('membership watch ended')
            if seed is not None:seed.poll()
            if now>=next_config:
                next_config=now+1;stamp=config_identity()
                received=refresh.take(stamp)
                if received is not None and received[1]==configuration:
                    # An unrelated firewall/DHCP/UI edit needs no PF mutation.
                    last_config=received[0];received=None
                if received is not None:
                    stamp,new=received;new_names=tuple(dict.fromkeys((*native.names,*('da_'+p['name'] for p in new))))
                    added=set(new_names)-set(native.names)
                    try:
                        if added:
                            if len(new_names)>128:raise ValueError('restart feed to retire deleted table identities')
                            _table_create(sorted(added));protect(new_names)
                            with member,writer.lock:native.extend_empty(new_names)
                        writer.replace_policies([Policy(p['name'],tuple(p['names'])) for p in new if p['enabled']],deadline=time.monotonic()+POLICY_APPLY_SECONDS)
                    except ReloadBusy:
                        # Only pre-processing lock refusal is retryable. Keep
                        # the accepted snapshot without repeated PHP reads;
                        # take() discards it if the saved config changes again.
                        if writer.state!='ready':raise
                        refresh.defer_apply(received)
                    else:
                        # Delete first disables/drains the policy. Retire its empty
                        # identity so later native reloads may remove its PF table.
                        configured=tuple('da_'+p['name'] for p in new)
                        if not configured:
                            configuration=[];stopping=True;return True
                        if set(configured)!=set(native.names):
                            with member,writer.lock:native.forget_empty(configured)
                            protect(configured)
                        previous_exact={(p['name'],n) for p in configuration if p['enabled'] for n in p['names'] if not n.startswith('*.')}
                        fresh_exact=tuple(dict.fromkeys(n for p in new if p['enabled'] for n in p['names'] if not n.startswith('*.') and (p['name'],n) not in previous_exact))
                        if fresh_exact:
                            from .seedqueries import SeedQueries
                            if seed is not None:seed.close(cancelled=True)
                            seed=SeedQueries(fresh_exact[:8],inspected['dns_port'],budget_seconds=.5,cancel_requested=lambda:stopping)
                        configuration=new;last_config=stamp
                if stamp!=last_config:refresh.request(stamp)
            if now>=next_status:
                next_status=now+2
                state.update(updated_utc=time.time(),table_counts={n:len(v) for n,v in native.known.items()},
                    policies=configuration,leases=len(ledger.leases),proofs=len(ledger.proofs),telemetry=feed.telemetry.status() if feed.telemetry else None,
                    reply_ack=feed.service.pump.status()['counters'] if feed.service and feed.service.pump else None,
                    reply_loss=feed.owner.reply_loss_status(),
                    expiry=feed.owner.expiry_status(),
                    settings_refresh=refresh.status(),
                    deployment_audit=feed.service.auditor.last_evidence if feed.service else None)
                state['confirmation']=confirmation.status() if confirmation is not None else {'state':'not_enabled'}
                write_json(DATA/'alias-status.json',state)
            return stopping
        result=run_feed(inspected,feed=feed,emit=event,cancel_requested=control,runtime_audit_seconds=60)
        state.update(state='stopped' if result['state'] in ('complete','cancelled') and result['restoration_verified'] and result['resources_released'] and not result.get('observation_failure') else 'failed',
            result=result,error=result.get('error') or result.get('observation_failure') or (result.get('feed',{}).get('cleanup') or {}).get('error'))
        if seed is not None:seed.close(cancelled=True)
        if result.get('restoration_verified'):
            rollback=result['rollback']
            manage.retire_completed_trial(rollback['journal_file_sha256'],worker_stopped=rollback.get('worker_exited') is True and rollback.get('worker_exit_code')==0,
                root=ROOT,data=DATA,ancestor_uids=tuple(dict.fromkeys((0,inspected['control_uid'],*[s['uid'] for s in inspected['sources']]))))
    except Exception as exc:
        state.update(state='failed',error=type(exc).__name__+': '+str(exc)[:200])
    finally:
        if refresh is not None and not refresh.close():state['settings_reader_cleanup_pending']=True
        if confirmation is not None:confirmation.close()
        if writer is not None:writer.close()
        if native is not None:native.close()
        if watcher is not None:
            if not watcher.stdin.closed:watcher.stdin.close()
            try:watcher.wait(timeout=6)
            except subprocess.TimeoutExpired:state['cleanup_error']='membership watch still running'
        if confirmation is not None and watcher is not None and watcher.poll() is not None:
            if result is not None and result.get('restoration_verified') and result.get('resources_released'):
                try:confirmation.retire()
                except Exception as exc:state['confirmation_cleanup_error']=type(exc).__name__
            else:state['confirmation_cleanup_error']='hook cleanup unverified; retained owned resources'
        if member is not None:member.close()
        # Only our exact fixed runtime gate files, after the watcher has exited.
        if descriptor is not None and watcher is not None and watcher.poll() is not None:
            for name in ('membership.gate','membership.disarmed'):
                path=RUNTIME/name
                if path.exists():path.unlink()
            try:RUNTIME.rmdir()
            except OSError:pass
        state['updated_utc']=time.time();state['tables']={};write_json(DATA/'alias-status.json',state)
        os.close(lock)


def main():
    p=argparse.ArgumentParser();p.add_argument('operation',choices=('start','stop','status','run'));args=p.parse_args()
    if os.geteuid()!=0 or not sys.platform.startswith('freebsd'):raise ValueError('native root service required')
    if current(ROOT,DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(ROOT/'dnsalias/lifecycle.py'),'alias',args.operation])
    if args.operation=='run':run()
    else:print(json.dumps(globals()[args.operation]()))


if __name__=='__main__':main()
