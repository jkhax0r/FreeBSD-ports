"""Owned native rc.d startup and quiescent-session reconciliation.

Never restore IP leases or firewall states. A new feed always learns fresh
remaining TTLs. Recovery never repeats an old reload or changes foreign hooks.
"""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import time

from .collector import write_json
from .sourceaudit import SourceAudit,SourceSpec
from .lifecycle import current,guarded

RC=Path('/usr/local/etc/rc.d/dnsalias.sh')
MARKER='dnsalias-native-service-1'


def body(root):
    return ('#!/bin/sh\n# DNS Alias owned native service\ncd '+shlex.quote(str(root))+' || exit 1\n'
            'exec /usr/local/bin/python3.11 -B '+shlex.quote(str(Path(root)/'dnsalias/lifecycle.py'))+' service "$1"\n').encode()


def legacy_body(root):
    # Exact wrapper shipped before the pre-import lifetime entry existed.
    # New serviceboot.main immediately execs that entry before any action.
    return ('#!/bin/sh\n# DNS Alias owned native service\ncd '+shlex.quote(str(root))+' || exit 1\n'
            'exec /usr/local/bin/python3.11 -B -m dnsalias.serviceboot "$1"\n').encode()


def _json(path,limit=4*1024*1024):
    spec=SourceSpec('owned_service_data',str(path),os.geteuid(),os.getegid(),(0o600,),limit)
    with SourceAudit([spec],ancestor_uids=tuple(dict.fromkeys((0,os.geteuid())))) as audit:
        raw=path.read_bytes();audit.audit()
    return json.loads(raw)


def registration(root,data,rc=RC):
    root,data,rc=map(Path,(root,data,rc));marker=data/'SERVICE.json'
    if not marker.exists():
        if rc.exists() or rc.is_symlink():raise ValueError('existing unowned service script')
        return None
    value=_json(marker,4096)
    expected=[{'owner':MARKER,'root':str(root),'path':str(rc),'sha256':hashlib.sha256(raw).hexdigest()} for raw in (body(root),legacy_body(root))]
    if value not in expected:raise ValueError('service ownership marker changed')
    info=rc.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1
        or stat.S_IMODE(info.st_mode)!=0o755 or rc.read_bytes() not in (body(root),legacy_body(root)) or hashlib.sha256(rc.read_bytes()).hexdigest()!=value['sha256']):
        raise ValueError('owned service script changed')
    return value


@guarded(control=True)
def enable(root,data,rc=RC):
    import manage
    root,data,rc=map(Path,(root,data,rc));manage.verify(root,data)
    if registration(root,data,rc) is not None:return {'boot_enabled':True,'changed':False}
    raw=body(root);fd=os.open(rc,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o755)
    try:
        os.fchmod(fd,0o755)
        if os.write(fd,raw)!=len(raw):raise OSError('short service script write')
        os.fsync(fd)
    finally:os.close(fd)
    value={'owner':MARKER,'root':str(root),'path':str(rc),'sha256':hashlib.sha256(raw).hexdigest()}
    fd=os.open(data/'SERVICE.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        os.fchmod(fd,0o600);encoded=json.dumps(value).encode()
        if os.write(fd,encoded)!=len(encoded):raise OSError('short service registration write')
        os.fsync(fd)
    finally:os.close(fd)
    registration(root,data,rc)
    return {'boot_enabled':True,'changed':True,'service_started':False}


@guarded(control=True)
def disable(root,data,rc=RC):
    root,data,rc=map(Path,(root,data,rc))
    if registration(root,data,rc) is not None:
        rc.unlink();(data/'SERVICE.json').unlink()
    return {'boot_enabled':False,'running_service_stopped':False}


def _not_our_process(pid):
    if type(pid) is not int or pid<=1:raise ValueError('recorded process identity required')
    p=subprocess.run(['/bin/ps','-ww','-p',str(pid),'-o','command='],capture_output=True,text=True,timeout=1)
    # FreeBSD ps returns1 with no output for a reaped PID. A failed/warned
    # inspection is not that proof, and must not permit recovery or PID unlink.
    if p.returncode==1 and not p.stdout and not p.stderr:return
    if p.returncode!=0 or p.stderr or not p.stdout.strip() or len(p.stdout)>16384:
        raise ValueError('prior process status unavailable; inspect before recovery')
    # Current workers execute the installed lifecycle path rather than -m.
    # Keep the legacy module spelling and refuse either package command form.
    if 'dnsalias.' in p.stdout or '/dnsalias/' in p.stdout:
        raise ValueError('prior DNS Alias helper is still running')


def temporary_readiness_error(error):
    from .runtimecontrol import RuntimeControlError
    if isinstance(error,(ConnectionError,TimeoutError,FileNotFoundError)):return True
    return isinstance(error,RuntimeControlError) and (isinstance(error.__cause__,(ConnectionError,TimeoutError)) or 'deadline' in str(error))


def reconcile(root,data):
    """Retire one stopped, verified-original session, preserving its evidence."""
    import manage
    from .aliasservice import process,target,saved,RUNTIME
    from .bootidentity import capture
    from .hookplan import state as hook_state
    from .membershipgate import ExclusiveMembershipGate
    from .pfapi import NativePFTables
    root,data=map(Path,(root,data));manage.verify(root,data)
    if process() is not None:raise ValueError('stop the alias owner before reconciliation')
    previous=manage.inspect_trial_directory(root,data)
    if previous is None:return {'reconciled':False}
    if previous['pending_file'] or previous['record'] is None:raise ValueError('partial journal requires inspection')
    record=previous['record'];plan=record['checkpoint']['plan'];worker=record['checkpoint']['status']['worker']
    if worker is not None:_not_our_process(worker['pid'])
    last=_json(data/'alias-status.json')
    if last.get('guard_pid') is not None:_not_our_process(last['guard_pid'])
    policies=saved(root);names=tuple('da_'+p['name'] for p in policies)
    if names:
        with NativePFTables('',names) as native:
            if any(native.snapshot().values()):raise ValueError('old table memberships remain; inspect cleanup')
    gate=None
    if RUNTIME.exists():
        descriptor=last.get('membership_gate')
        if descriptor is None or set(p.name for p in RUNTIME.iterdir())!={'membership.disarmed'}:
            raise ValueError('unqualified prior membership runtime')
        gate=ExclusiveMembershipGate(descriptor,disarmed=True)
        with gate:pass
    spec=SourceSpec(**(plan['hook']|{'modes':tuple(plan['hook']['modes'])}))
    # pfSense may chown /var/unbound to its service account at resolver start.
    # Match target()'s explicit trusted ancestor set; hook bytes remain exact.
    with SourceAudit([spec],ancestor_uids=tuple(dict.fromkeys((0,spec.uid,pwd.getpwnam('unbound').pw_uid)))) as audit:
        current=Path(spec.path).read_bytes();audit.audit();state=hook_state(current,plan['overlay'])
        if state=='owned_overlay' and capture()['boot_id']!=plan['boot_id']:
            from .plainsetup import exchange_owned
            exchange_owned(data,audit,plan['overlay']);state='original_restored'
        if state!='original_restored':raise ValueError('hook is not the original policy; inspect before recovery')
    inspected=target(root,data)
    if inspected['mode']=='pfblockerng' and inspected['expected_sources']['selected_hook']!=inspected['expected_sources']['policy_vendor_hook']:
        raise ValueError('vendor hook differs from current original policy')
    # Preserve the previous outcome as previous, never mark its uncertain
    # action complete or carry a single address into the new session.
    write_json(data/'alias-last-session.json',{'format':'dnsalias-quiescent-recovery-1',
        'reconciled_utc':time.time(),'prior_record':record,'old_reload_retried':False,'old_leases_adopted':False})
    if manage.inspect_trial_directory(root,data)['record']!=record:raise ValueError('journal changed during reconciliation')
    if gate is not None:
        gate.close();(RUNTIME/'membership.disarmed').unlink();RUNTIME.rmdir()
    path=data/manage.TRIAL_DIRECTORY
    for name in previous['files']:(path/name).unlink()
    path.rmdir()
    return {'reconciled':True,'old_reload_retried':False,'old_leases_adopted':False}


def _old_boot_pidfiles(data):
    from .bootidentity import capture
    boot=capture()['boot_utc']
    for name in ('alias-service.pid','collector.pid'):
        path=Path(data)/name
        if not path.exists():continue
        info=path.lstat()
        if info.st_mtime>=boot:continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_size>32:
            raise ValueError('old service PID file ownership changed')
        raw=path.read_text().strip()
        if not raw.isdigit() or int(raw)<=1:raise ValueError('invalid prior boot PID file')
        _not_our_process(int(raw));path.unlink()


def main():
    from .aliasservice import ROOT,DATA,process,saved,start,stop,target
    import manage
    p=argparse.ArgumentParser();p.add_argument('action',choices=('start','stop','enable','disable','status'));a=p.parse_args()
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root service control required')
    if current(ROOT,DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(ROOT/'dnsalias/lifecycle.py'),'service',a.action])
    if a.action=='enable':
        code="require_once '/etc/inc/config.inc';require_once '/etc/inc/functions.inc';require_once '/etc/inc/pkg-utils.inc';echo json_encode(RCFILEPREFIX);"
        native=subprocess.run(['/usr/local/bin/php','-r',code],capture_output=True,text=True,timeout=3)
        if native.returncode or json.loads(native.stdout)!=str(RC.parent)+'/':raise ValueError('unqualified native service directory')
        result=enable(ROOT,DATA)
    elif a.action=='disable':result=disable(ROOT,DATA)
    elif a.action=='status':result={'boot_enabled':registration(ROOT,DATA) is not None}
    elif a.action=='stop':
        result=stop(wait=True)
        manage.stop(ROOT,DATA);result['stopped']=True
    else:
        manage.verify(ROOT,DATA);_old_boot_pidfiles(DATA)
        setting=subprocess.run(['/usr/local/bin/php',str(ROOT/'native/policies.php'),'service-enabled'],capture_output=True,text=True,timeout=2)
        if setting.returncode or setting.stdout.strip() not in ('true','false'):raise ValueError('service enable setting unavailable')
        if setting.stdout.strip()=='false':
            print(json.dumps({'disabled':True,'started':False}));return
        if process() is None:
            from .plainenable import ensure as ensure_plain_hook
            ensure_plain_hook(ROOT,DATA)
        if process() is not None:result={'already_running':True}
        elif not saved(ROOT):
            if manage.owned_process(ROOT,DATA) is None:manage.start(0,ROOT,DATA)
            result={'no_aliases_configured':True}
        else:
            until=time.monotonic()+60
            # Only read-only readiness checks are repeated. No hook or table
            # mutation begins before readiness and prior-session review.
            while True:
                try:
                    if manage.inspect_trial_directory(ROOT,DATA) is not None:reconcile(ROOT,DATA)
                    else:target(ROOT,DATA)
                    break
                except Exception as exc:
                    if not temporary_readiness_error(exc) or time.monotonic()>=until:raise
                    time.sleep(1)
            if manage.owned_process(ROOT,DATA) is None:manage.start(0,ROOT,DATA)
            result=start() if saved(ROOT) else {'no_aliases_configured':True}
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception as exc:
        print('DNS Alias service: '+str(exc)[:500],file=sys.stderr)
        raise SystemExit(1)
