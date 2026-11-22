"""Explicit independent watchdog for one bound registered membership session.

Start this worker BEFORE giving its feed child any request. The single-threaded
parent owns and does not reap that child until the protected PID acknowledgement.
Pulses carry the feed loop's monotonic time, never receipt time. A fixed startup
deadline also covers a feed that never emits a pulse. No automatic recovery,
service installation, main-rule reload or adoption of an earlier session.
"""
import json
import math
import os
from pathlib import PurePosixPath
import select
import sys
import time

from .aliascoordinator import SavedAliasAuthority
from .blocktrial import ScopedBlockRule,validate as validate_rule
from .membershipgate import ExclusiveMembershipGate,validate as validate_gate
from .processwatch import ProcessLifetimeWatch
from .registeredcleanup import DrainFailure,run_once
from .reloadlock import SharedReloadLock,ExclusiveConfigLock,ReloadBusy
from .trialtable import _Receipt as TableReceipt


def number(value):
    return type(value) in (int,float) and math.isfinite(value)


def validate(plan,*,now,parent_pid):
    required={'root','data','config','table','directory','membership_gate','reload_lock_path',
              'config_lock_path','parent_pid','deadline','startup_seconds','heartbeat_seconds','consumer'}
    optional={'rule','gate_path','gate_inode','block_seconds'}
    if type(plan) is not dict or set(plan)!=required|(optional if plan.get('consumer') is True else set()):
        raise ValueError('complete registered guard plan required')
    if type(plan['consumer']) is not bool or type(plan['parent_pid']) is not int or plan['parent_pid']!=parent_pid:
        raise ValueError('explicit consumer and live direct parent required')
    if not number(now) or not number(plan['deadline']) or not now<plan['deadline']<=now+86400:
        raise ValueError('bounded original registered deadline required')
    for key,low,high in (('startup_seconds',1,15),('heartbeat_seconds',1,3)):
        if not number(plan[key]) or not low<=plan[key]<=high:raise ValueError('bounded guard timing required')
    for key in ('root','data','config','directory','reload_lock_path','config_lock_path'):
        if type(plan[key]) is not str or not PurePosixPath(plan[key]).is_absolute():raise ValueError('explicit absolute guard paths required')
    descriptor=validate_gate(plan['membership_gate'])
    if PurePosixPath(descriptor['path']).parent!=PurePosixPath(plan['directory']):raise ValueError('exact membership session required')
    if plan['consumer']:
        spec=validate_rule(plan['rule'])
        if (spec['table']!=plan['table'] or 'policy_name' not in spec
            or plan['gate_path']!=str(PurePosixPath(plan['directory'])/'gate')
            or type(plan['block_seconds']) is not int or not 5<=plan['block_seconds']<=3600):
            raise ValueError('same bounded owned consumer required')
    return dict(plan)


class Health:
    """Fixed-deadline command admission; no IO, kernel access or renewed TTLs."""
    def __init__(self,plan,now):
        self.deadline=plan['deadline'];self.startup_until=min(self.deadline,now+plan['startup_seconds'])
        self.heartbeat_seconds=plan['heartbeat_seconds'];self.last_pulse=None;self.qualified=False
        self.bound=False;self.activation=False;self.stopping=False

    def bind(self):
        if self.bound or self.stopping:raise ValueError('one fresh dependency binding required')
        self.bound=True

    def pulse(self,stamp,qualified,now):
        if (not self.bound or self.stopping or not number(stamp) or type(qualified) is not bool
            or not 0<=now-stamp<=1 or self.last_pulse is not None and stamp<=self.last_pulse):
            raise ValueError('fresh ordered feed-loop pulse required')
        if self.qualified and not qualified:self.stopping=True
        self.last_pulse=stamp;self.qualified=self.qualified or qualified

    def activate(self,now,seconds):
        if self.stopping or self.activation or not self.qualified or self.reason(now) is not None:
            raise ValueError('one protected healthy activation required')
        self.activation=True;self.deadline=min(self.deadline,now+seconds+5)

    def reason(self,now):
        if now>=self.deadline:return 'deadline'
        if self.stopping:return 'heartbeat_expired'
        if not self.qualified and now>=self.startup_until:return 'heartbeat_expired'
        if self.last_pulse is not None and now-self.last_pulse>=self.heartbeat_seconds:return 'heartbeat_expired'
        return None


def worker(plan,*,control_fd=0,emit=None):
    """Root-only explicit child worker. A successful exit means verified drain.

    The actual feed PID is bound before its first request. This API cannot prove
    its caller's child ownership: the parent must retain its unreaped Popen child
    and wait for protected before allowing any writer construction/startup replay.
    """
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root registered guard required')
    now=time.monotonic();plan=validate(plan,now=now,parent_pid=os.getppid());health=Health(plan,now)
    emit=emit or (lambda value:print(json.dumps(value),flush=True))
    watches=[];rule=fence=review_reload=review_config=None;expected=None;buffer=b'';next_stats=next_health=0;owned=False
    outcome={'active':False,'activated':False,'removed':not plan['consumer'],'reason':None,
             'error':None,'membership_drained':False,'protected':False}
    authority=None
    def alive():return all(item.alive() for item in watches)
    try:
        watches.append(ProcessLifetimeWatch(plan['parent_pid']))
        authority=SavedAliasAuthority(root=plan['root'],data=plan['data'],config=plan['config'],table=plan['table'])
        descriptor=plan['membership_gate']
        if (descriptor['uid'],descriptor['gid'])!=(0,0):raise ValueError('root-owned membership gate required')
        fence=ExclusiveMembershipGate(descriptor)
        # Verify empty-session ownership and definitions before telling the
        # parent it may bind a feed. No writer is admitted at this stage.
        review_reload=SharedReloadLock(plan['reload_lock_path']);review_config=ExclusiveConfigLock(plan['config_lock_path'])
        with fence,review_reload as reload,review_config as config:
            authority.review(reload,config)
            with TableReceipt(plan['directory'],expected_uid=0) as receipt:
                value=receipt.read()
                if value is None:raise ValueError('acquired registered table binding missing')
                owner=value['checkpoint']
                if (owner.get('phase')!='acquired' or owner.get('membership_gate')!=descriptor
                    or owner.get('registration_receipt_sha256')!=authority.digest
                    or owner.get('registration_boot_id')!=authority.boot
                    or owner.get('rule',{}).get('table')!=authority.table
                    or plan['consumer'] and owner.get('rule')!=plan['rule']):
                    raise ValueError('exact acquired table/gate binding required')
                owned=True
        if plan['consumer']:
            rule=ScopedBlockRule(plan['rule'],gate_path=plan['gate_path'],gate_inode=plan['gate_inode'],
                                 reload_lock_path=plan['reload_lock_path'])
            expected=rule.prepare()
        emit({'event':'ready','canonical_rule':expected,'membership_guard':True})
        while True:
            now=time.monotonic()
            reason=health.reason(now)
            if reason is not None:outcome['reason']=reason;break
            if not watches[0].alive():outcome['reason']='parent_lost';break
            if len(watches)==2 and not watches[1].alive():outcome['reason']='writer_lost';break
            if health.bound and now>=next_health:
                next_health=now+.5;emit({'event':'health','monotonic':now})
            if outcome['active'] and now>=next_stats:
                next_stats=now+5
                try:sample=rule.counters()
                except ReloadBusy:sample=False;next_stats=now+.5
                if sample is None:outcome['reason']='rule_absent';break
                if sample is not False:outcome['counters']=sample;emit({'event':'counters','counters':sample})
            ready,_,_=select.select([control_fd],[],[],min(.1,max(0,health.deadline-now)))
            if not ready:continue
            chunk=os.read(control_fd,1024)
            if not chunk:outcome['reason']='parent_lost';break
            buffer+=chunk
            if len(buffer)>2048:raise ValueError('registered guard command buffer exceeded')
            lines=0
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1);lines+=1
                if len(line)>128 or lines>16:raise ValueError('bounded registered guard commands required')
                command=line.decode('ascii').split(' ');now=time.monotonic()
                if health.reason(now) is not None:outcome['reason']=health.reason(now);break
                if len(command)==2 and command[0]=='bind':
                    if not command[1].isdigit():raise ValueError('explicit dependency PID required')
                    pid=int(command[1])
                    if pid in (os.getpid(),plan['parent_pid']):raise ValueError('distinct owned feed child required')
                    health.bind();watches.append(ProcessLifetimeWatch(pid))
                    outcome['protected']=True;emit({'event':'protected','pid':pid})
                elif len(command)==3 and command[0]=='pulse' and command[2] in ('0','1'):
                    health.pulse(float(command[1]),command[2]=='1',now)
                    if health.stopping:outcome['reason']='heartbeat_expired';break
                elif command==['activate'] and rule is not None:
                    health.activate(now,plan['block_seconds'])
                    outcome.update(rule.activate(deadline=health.deadline,alive=alive));outcome['activated']=True
                    emit({'event':'active'})
                elif command==['undo']:outcome['reason']='undo';break
                else:raise ValueError('unknown or repeated registered guard command')
            if outcome['reason'] is not None:break
    except Exception as exc:
        outcome['error']=type(exc).__name__
        outcome['reason']=outcome['reason'] or 'heartbeat_expired'
    finally:
        # A fixed cleanup phase lets the parent allow the existing bounded
        # fence/drain/removal budgets without mistaking them for a stalled loop.
        # A failed status write must never prevent independent cleanup.
        try:emit({'event':'stopping','monotonic':time.monotonic()})
        except Exception:pass
        if owned and fence is not None and authority is not None:
            try:
                # Busy acquisition is known unexecuted. Bound waiting never
                # repeats a rename, durable drain intent or kernel operation.
                until=time.monotonic()+2
                while True:
                    try:fence.__enter__();break
                    except ReloadBusy:
                        if time.monotonic()>=until:raise
                        time.sleep(.02)
                try:
                    outcome['membership_disarm']=fence.disarm()
                    outcome['membership_drain']=run_once(authority,fence,directory=plan['directory'],
                        reload_lock_path=plan['reload_lock_path'],config_lock_path=plan['config_lock_path'],
                        reason=outcome['reason'] or 'heartbeat_expired')
                    outcome['membership_drained']=True
                finally:fence.__exit__()
            except DrainFailure as exc:
                outcome['drain_error']={'stage':exc.stage,'mutation_attempted':exc.mutation_attempted,'empty_verified':exc.empty_verified}
            except Exception as exc:outcome['drain_error']={'type':type(exc).__name__}
        if rule is not None and expected is not None:
            try:
                until=time.monotonic()+2
                while True:
                    try:outcome.update(rule.disarm(expected));outcome['active']=False;break
                    except ReloadBusy:
                        if time.monotonic()>=until:raise
                        time.sleep(.02)
            except Exception as exc:outcome['cleanup_error']=type(exc).__name__
        if rule is not None:rule.close()
        if fence is not None:fence.close()
        for resource in (review_config,review_reload):
            if resource is not None:resource.close()
        for watch in watches:watch.close()
    emit({'event':'finished',**outcome});return outcome


if __name__=='__main__':
    data=bytearray()
    while len(data)<=8192:
        byte=os.read(0,1)
        if not byte:raise ValueError('registered guard plan missing')
        if byte==b'\n':break
        data.extend(byte)
    else:raise ValueError('registered guard plan too large')
    result=worker(json.loads(data))
    raise SystemExit(0 if result['membership_drained'] and result['removed'] and result['error'] is None else 1)
