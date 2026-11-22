"""Explicit short block trial supervisor; no installation or automatic startup.

Caller supplies a freshly inspected resolver target, an exclusively owned empty
root table/anchor, and a fresh private gate. It must preserve all prior security
decisions when selecting the source/interface/port and anchor order. This
single-threaded owner fences its two direct children before cleanup. The rule
worker independently expires and watches both this process and the feed. The
feed's separate existing worker restores the original DNS hook on exit/deadline.

The caller retains package/data/table/gate on uncertain restoration or cleanup.
This module never creates aliases, rules outside the supplied one-rule anchor,
PF tables, firewall states, persistent configuration or boot registrations.
"""
import ipaddress
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import traceback

from .blocktrial import ScopedBlockRule,validate as validate_rule
from .leases import dns_name
from .pfapi import NativePFTables
from .reloadlock import ReloadBusy
from .trialservice import validate_target
from .writerfence import OwnedWriterFence
from .seedqueries import SeedQueries
from .replygate import clock


class _GuardHeartbeat:
    """2s owned-pipe liveness; one announced cleanup phase has a fixed7s cap.

    Sender timestamps, not receipt times, bound both phases. Health messages
    stay in memory and are never emitted as UI checkpoint writes.
    """
    def __init__(self,now):self.started=self.previous=clock(now);self.last=self.stopping=None

    def _now(self,now):
        now=clock(now)
        if now<self.previous:raise ValueError('guard heartbeat clock regressed')
        self.previous=now;return now

    def accept(self,value,now):
        now=self._now(now)
        if type(value) is not dict or set(value)!={'event','monotonic'} or value['event'] not in ('health','stopping'):
            raise ValueError('exact guard heartbeat required')
        stamp=clock(value['monotonic'])
        if self.stopping is not None or not 0<=now-stamp<=1 or self.last is not None and stamp<=self.last:
            raise ValueError('fresh increasing guard heartbeat required')
        self.last=stamp
        if value['event']=='stopping':self.stopping=stamp

    def expired(self,now):
        now=self._now(now)
        if self.stopping is not None:return now-self.stopping>=7
        return now-(self.started if self.last is None else self.last)>=2


class _Reader:
    def __init__(self,pipe):self.pipe=pipe;self.buffer=b'';self.eof=False
    def take(self):
        if self.eof:return []
        ready,_,_=select.select([self.pipe],[],[],0)
        if not ready:return []
        chunk=os.read(self.pipe.fileno(),65536)
        if not chunk:
            self.eof=True
            if self.buffer:raise ValueError('truncated child report')
            return []
        self.buffer+=chunk
        if len(self.buffer)>131072:raise ValueError('child report size cap')
        values=[]
        while b'\n' in self.buffer:
            line,self.buffer=self.buffer.split(b'\n',1)
            value=json.loads(line)
            if type(value) is not dict:raise ValueError('child report object required')
            values.append(value)
        return values


class _Cancellation:
    """Latch an explicit request; caller's probe must be fast and nonblocking."""
    def __init__(self,probe):
        if probe is not None and not callable(probe):raise ValueError('optional cancellation probe required')
        self.probe=probe;self.requested=False

    def poll(self):
        if not self.requested and self.probe is not None:
            value=self.probe()
            if type(value) is not bool:raise ValueError('explicit boolean cancellation required')
            self.requested=value
        return self.requested


def _names_edit(value,policy):
    from .leases import Policy
    if (type(value) is not dict or set(value)!={'revision','names'}
        or type(value['revision']) is not int or not 0<=value['revision']<16
        or type(value['names']) is not list or not 1<=len(value['names'])<=8
        or any(type(n) is not str for n in value['names'])):
        raise ValueError('bounded names-only edit required')
    names=Policy(policy,tuple(value['names'])).patterns
    if len(set(names))!=len(names):raise ValueError('distinct policy names required')
    return {'revision':value['revision'],'names':list(names)}


class _FeedCommands:
    """One queued owner-loop edit, no thread, retry, rule or lifetime changes."""
    def __init__(self,reader,feed,policy,emit):
        self.reader,self.feed,self.policy,self.emit=reader,feed,policy,emit
        self.stopped=False;self.pending=None;self.revision=0;self.queued_at=None

    def poll(self):
        from .leases import Policy
        for command in self.reader.take():
            if command=={'op':'stop'}:self.stopped=True;continue
            if type(command) is not dict or command.get('op')!='names':raise ValueError('fixed feed control command required')
            edit=_names_edit({k:v for k,v in command.items() if k!='op'},self.policy)
            if self.pending is not None or edit['revision']!=self.revision:raise ValueError('one fresh feed edit required')
            self.pending=edit;self.queued_at=time.monotonic()
        if self.reader.eof:self.stopped=True
        if self.stopped:return True
        if self.pending is not None:
            service=self.feed.service
            if time.monotonic()-self.queued_at>2:raise TimeoutError('feed edit was not admitted before its deadline')
            if service is not None and service.state=='running' and service.pump.drained:
                policy=Policy(self.policy,tuple(self.pending['names']))
                if not service.session.reconfigure([policy],deadline=time.monotonic()+.04):
                    raise RuntimeError('feed edit synchronization requires cleanup')
                self.revision+=1
                self.emit({'event':'names_updated','revision':self.revision,'names':self.pending['names']})
                self.pending=None
        return False


def _seed_queries(names,port,*,cancel_requested=lambda:False,budget_seconds=2):
    """One Start-triggered lookup per exact name/family, outside DNS callbacks.

    These ordinary loopback DNS answers still pass through the authenticated
    hook and remaining-TTL ledger. This worker cannot insert table members.
    There is no periodic refresh, cache dump, direct IP authorization or retry.
    The supervisor must retain exclusive single-threaded child ownership.
    Initial lookups run only at Start, check Undo between queries, and share
    a two-second total budget. The separate feed processes DNS and PF ACKs.
    """
    from .dnscheck import query
    if type(budget_seconds) not in (int,float) or not .05<=budget_seconds<=2:raise ValueError('bounded seed budget required')
    out={'attempted':0,'answered':0,'failed':0,'cancelled':False,'budget_exhausted':False,
         'direct_membership_writes':False,'periodic_refresh':False,'background_thread':False}
    deadline=time.monotonic()+budget_seconds
    for name in names:
        if name.startswith('*.'):continue
        for kind in (1,28):
            if cancel_requested():out['cancelled']=True;return out
            remaining=deadline-time.monotonic()
            if remaining<=0:out['budget_exhausted']=True;return out
            out['attempted']+=1
            try:query(name,kind=kind,port=port,timeout_seconds=min(.2,remaining));out['answered']+=1
            except (OSError,ValueError):out['failed']+=1
    return out


def _no_match(activated,guard_result):
    return (activated is False and type(guard_result) is dict
        and guard_result.get('activated') is False and guard_result.get('removed') is True
        and guard_result.get('error') is None and guard_result.get('reason')=='deadline')


def run(target,rule_spec,names,*,gate_path,gate_inode,reload_lock_path,emit=None,cancel_requested=None,block_seconds=5,names_update_requested=None,
        registered_authority=None,membership_gate=None):
    """Five-second trial; cancellation stops activation and requests scoped undo.

    Cancellation is latched. The feed still completes its bounded original-hook
    restoration, and the independent rule expiry remains unchanged. Completion
    is reported only after restoration and scoped cleanup, not on button receipt.
    No browser/user values belong in target, rule, paths or deadlines directly.
    """
    target=validate_target(target);spec=validate_rule(rule_spec)
    cancellation=_Cancellation(cancel_requested)
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('qualified native root supervisor required')
    named='policy_name' in spec
    registered=registered_authority is not None
    if registered:
        from .aliascoordinator import SavedAliasAuthority
        from .membershipgate import validate as validate_membership_gate
        if (type(registered_authority) is not SavedAliasAuthority or not named
            or registered_authority.root!=Path(target['root']) or registered_authority.data!=Path(target['data'])
            or registered_authority.table!=spec['table']):raise ValueError('exact registered session authority required')
        membership_gate=validate_membership_gate(membership_gate)
        if Path(membership_gate['path']).parent!=Path(gate_path).parent:raise ValueError('same registered runtime required')
    elif membership_gate is not None:raise ValueError('membership gate requires registered authority')
    if names_update_requested is not None and (not named or not callable(names_update_requested)):
        raise ValueError('optional names-only source requires named policy')
    if type(block_seconds) is not int or (block_seconds!=5 and (not named or not 60<=block_seconds<=3600)):
        raise ValueError('explicit bounded named policy duration required')
    if (block_seconds==5 and target['duration_seconds']>30 or block_seconds!=5
        and not block_seconds+10<=target['duration_seconds']<=block_seconds+30):raise ValueError('feed duration must bind policy duration')
    if type(names) not in (tuple,list) or not 1<=len(names)<=8:raise ValueError('bounded exact test domains required')
    if named:
        from .leases import Policy
        names=Policy(spec['policy_name'],tuple(names)).patterns
    else:names=tuple(dns_name(name) for name in names)
    if len(set(names))!=len(names):raise ValueError('unique test domains required')
    if emit is not None and not callable(emit):raise ValueError('bounded event receiver required')
    emit=emit or (lambda event:None)
    import manage
    root,data=Path(target['root']),Path(target['data'])
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('exact installed supervisor package required')
    manage.verify(root,data)
    if manage.inspect_trial_directory(root,data) is not None:raise ValueError('prior trial requires inspection')
    rule=ScopedBlockRule(spec,gate_path=gate_path,gate_inode=gate_inode,reload_lock_path=reload_lock_path)
    table=None;feed=guard=feed_fence=guard_fence=feed_reader=guard_reader=seed=None;seed_kind='initial'
    feed_result=guard_result=None;guard_health=None;expected=None;activated=False;undo_sent=False
    active_at=None;guard_deadline=None;ready=False;feed_closed=False;next_members=0;last_members=None;last_member_event=0
    last_health=None;health_failed=False;feed_stop_sent=False;pending_edit=None;names_revision=0;qualified_guard_pulse=False
    out={'format':'dnsalias-short-block-trial-1','state':'preflight','error':None,
         'enforcement_applied':None,'rule_activated':False,'traffic_verified':False,'rule_removed':False,'restoration_verified':False,
         'feed_result':None,'guard_result':None,'resources_released':False,'rule':spec,'names':names,
         'cancel_requested':False}
    deadline=time.monotonic()+target['duration_seconds']+25
    try:
        expected=rule.prepare()
        table=NativePFTables('',(spec['table'],))
        if table.snapshot()!={spec['table']:set()}:raise ValueError('caller-owned empty root table required')
        if registered:
            guard_deadline=time.monotonic()+target['duration_seconds']+10
            guard=subprocess.Popen([sys.executable,'-B','-m','dnsalias.registeredguard'],cwd=root,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            guard_fence=OwnedWriterFence(guard);guard_reader=_Reader(guard.stdout)
            plan={'root':str(root),'data':str(data),'config':str(registered_authority.config),'table':spec['table'],
                'directory':str(Path(gate_path).parent),'membership_gate':membership_gate,
                'reload_lock_path':reload_lock_path,'config_lock_path':'/tmp/config.lock','parent_pid':os.getpid(),
                'deadline':guard_deadline,'startup_seconds':15,'heartbeat_seconds':2,'consumer':True,
                'rule':spec,'gate_path':str(gate_path),'gate_inode':gate_inode,'block_seconds':block_seconds}
            guard.stdin.write((json.dumps(plan)+'\n').encode());guard.stdin.flush()
            until=time.monotonic()+3
            while not out.get('guard_ready') and time.monotonic()<until:
                for value in guard_reader.take():
                    if value.get('event')!='ready' or value.get('canonical_rule')!=expected:
                        if value.get('event')=='finished':guard_result=value
                        raise ValueError('registered guard preparation failed')
                    out['guard_ready']=True
                if guard_reader.eof:raise RuntimeError('registered guard ended before ready')
                time.sleep(.01)
            if not out.get('guard_ready'):raise TimeoutError('registered guard readiness deadline')
        feed=subprocess.Popen([sys.executable,'-B','-m','dnsalias.blockservice','--feed'],cwd=root,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
        feed_fence=OwnedWriterFence(feed);feed_reader=_Reader(feed.stdout)
        if registered:
            if feed_fence.inspect()['stopped']:raise RuntimeError('feed ended before protected binding')
            # Retain the unreaped owned child; do not poll it between this bind
            # and the independent watch acknowledgement. No request yet means
            # it cannot construct a writer or replay startup DNS answers.
            guard.stdin.write(('bind '+str(feed.pid)+'\n').encode());guard.stdin.flush()
            protected=False;until=time.monotonic()+2
            while not protected and time.monotonic()<until:
                for value in guard_reader.take():
                    if value=={'event':'protected','pid':feed.pid} and not protected:
                        protected=True;guard_health=_GuardHeartbeat(time.monotonic())
                    elif value.get('event') in ('health','stopping') and protected:
                        guard_health.accept(value,time.monotonic())
                    else:
                        if value.get('event')=='finished':guard_result=value
                        raise ValueError('registered feed protection failed')
                if guard_reader.eof:raise RuntimeError('registered guard ended before protection')
                time.sleep(.01)
            if not protected:raise TimeoutError('registered feed protection deadline')
            out['membership_protected_before_feed']=True
        payload={'target':target,'table':spec['table'],'names':names,'reload_lock_path':reload_lock_path,'sustained':named}
        if registered:payload['membership_gate']=membership_gate
        request=json.dumps(payload)+'\n'
        if len(request.encode())>32768:raise ValueError('feed request cap')
        feed.stdin.write(request.encode());feed.stdin.flush()
        if not named:feed.stdin.close()
        emit({'event':'feed_started','pid':feed.pid})
        out['state']='warming'
        while time.monotonic()<deadline:
            if cancellation.poll() and not out['cancel_requested']:
                out['cancel_requested']=True;out['state']='restoring'
                emit({'event':'undo_requested','rule_activated':activated,
                      'removal_verified':False,'restoration_verified':False})
            for value in feed_reader.take():
                if set(value)=={'result'}:feed_result=value['result']
                elif set(value)=={'event'}:
                    event=value['event']
                    if event.get('event')=='observing' and not ready:
                        ready=True
                        last_health=time.monotonic()
                        if cancellation.requested:continue
                        if not registered:
                            guard_deadline=time.monotonic()+block_seconds+5
                            guard=subprocess.Popen([sys.executable,'-B','-m','dnsalias.blocktrial'],cwd=root,
                                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
                            guard_fence=OwnedWriterFence(guard);guard_reader=_Reader(guard.stdout)
                            plan={'rule':spec,'gate_path':str(gate_path),'gate_inode':gate_inode,'reload_lock_path':reload_lock_path,
                                  'parent_pid':os.getpid(),'dependency_pid':feed.pid,'deadline':guard_deadline}
                            guard.stdin.write((json.dumps(plan)+'\n').encode());guard.stdin.flush()
                        emit({'event':'feed_ready','guard_pid':guard.pid,'names':names})
                        seed=(SeedQueries(names,target['dns_port'],cancel_requested=cancellation.poll) if named else
                              _seed_queries(names,target['dns_port'],cancel_requested=cancellation.poll))
                    elif event.get('event')=='rollback_ready':emit(event)
                    elif event.get('event')=='trial_phase':emit({'event':'hook_phase','phase':event['phase']})
                    elif named and event.get('event')=='names_updated':
                        if (pending_edit is None or event.get('revision')!=names_revision+1
                            or event.get('names')!=pending_edit['names']):raise ValueError('unexpected feed edit acknowledgement')
                        names_revision+=1;emit(event)
                        if isinstance(seed,SeedQueries):
                            seed.close(cancelled=True)
                            out['initial_lookups' if seed_kind=='initial' else 'latest_names_lookups']=seed.status()
                        seed=SeedQueries(event['names'],target['dns_port'],cancel_requested=cancellation.poll,budget_seconds=.5)
                        seed_kind='names'
                        out['names_updates']=names_revision;out['latest_names']=event['names'];pending_edit=None
                    elif named and event.get('event')=='feed_health':
                        stamp=event.get('monotonic');qualified=event.get('qualified')
                        if type(stamp) not in (int,float) or type(qualified) is not bool or not 0<=time.monotonic()-stamp<=2:
                            raise RuntimeError('unqualified feed health record')
                        if registered and guard_result is None:
                            if time.monotonic()-stamp>1:raise RuntimeError('stale registered feed loop pulse')
                            guard.stdin.write(('pulse '+str(stamp)+' '+str(int(qualified))+'\n').encode());guard.stdin.flush()
                            qualified_guard_pulse=qualified_guard_pulse or qualified
                        if ready and not qualified:health_failed=True
                        if qualified:last_health=stamp
                else:raise ValueError('unexpected feed report')
            if isinstance(seed,SeedQueries):
                seed.poll()
                if seed.done:out['initial_lookups' if seed_kind=='initial' else 'latest_names_lookups']=seed.status()
            if named and cancellation.requested and not feed_stop_sent:
                feed_stop_sent=True;feed.stdin.write(b'{"op":"stop"}\n');feed.stdin.flush();feed.stdin.close()
            if guard_reader is not None:
                for value in guard_reader.take():
                    event=value.get('event')
                    if registered and event in ('health','stopping'):
                        guard_health.accept(value,time.monotonic())
                    elif event=='ready':
                        if value.get('canonical_rule')!=expected:raise ValueError('guard preview changed')
                        out['guard_ready']=True
                    elif event=='active':
                        activated=True;active_at=time.monotonic();out['rule_activated']=True
                        if registered:guard_deadline=min(guard_deadline,active_at+block_seconds+5)
                        out['state']='restoring' if cancellation.requested else 'blocking'
                        members=table.snapshot()[spec['table']]
                        emit({'event':'block_active','members':sorted(members)[:128],'members_count':len(members),
                              'client':spec['client'],'port':spec['port']})
                    elif event=='finished':
                        guard_result=value;out['rule_removed']=value.get('removed') is True
                        out['end_reason']=value.get('reason')
                        if not out['rule_removed'] or value.get('error') is not None:raise RuntimeError('guard removal requires inspection')
                        if registered and value.get('membership_drained') is not True:raise RuntimeError('registered membership drain requires inspection')
                        emit({'event':'block_removed','reason':value.get('reason')})
                    elif event=='counters':
                        out['rule_counters']=value['counters'];emit({'event':'rule_counters','counters':value['counters']})
                    else:raise ValueError('unexpected guard report')
            if named and guard_result is not None and not feed_stop_sent:
                feed_stop_sent=True;feed.stdin.write(b'{"op":"stop"}\n');feed.stdin.flush();feed.stdin.close()
            if guard is not None and guard_result is None:
                if registered and guard_health.expired(time.monotonic()):
                    out['guard_heartbeat_expired']=True
                    raise RuntimeError('registered guard heartbeat ended')
                seed_ready=not isinstance(seed,SeedQueries) or seed.done
                if ready and seed_ready and out.get('guard_ready') and not out.get('activation_sent') and not cancellation.requested and (not registered or qualified_guard_pulse):
                    members=table.snapshot()[spec['table']]
                    family=ipaddress.ip_address(spec['client']).version
                    if named or any(ipaddress.ip_address(ip).version==family for ip in members):
                        if not feed_fence.inspect()['stopped'] and time.monotonic()<guard_deadline-1:
                            out['activation_sent']=True;guard.stdin.write(b'activate\n');guard.stdin.flush()
                # Never enqueue undo behind an unacknowledged activate: the
                # guard deliberately permits one outstanding command at a time.
                cancel_ready=(cancellation.requested and out.get('guard_ready')
                              and (not out.get('activation_sent') or activated))
                if named and ready and (health_failed or last_health is None or time.monotonic()-last_health>=2):
                    raise RuntimeError('qualified feed heartbeat ended')
                if not undo_sent and (cancel_ready or activated and time.monotonic()-active_at>=block_seconds or named and feed_result is not None):
                    undo_sent=True;guard.stdin.write(b'undo\n');guard.stdin.flush()
                if named and undo_sent and not feed_stop_sent:
                    feed_stop_sent=True;feed.stdin.write(b'{"op":"stop"}\n');feed.stdin.flush();feed.stdin.close()
                if time.monotonic()>guard_deadline+2:raise TimeoutError('rule worker deadline exceeded')
                if guard_reader.eof and guard_result is None:raise RuntimeError('guard exited without report')
            if named and activated and guard_result is None and time.monotonic()>=next_members:
                members=table.snapshot()[spec['table']];next_members=time.monotonic()+1
                if members!=last_members or time.monotonic()-last_member_event>=10:
                    last_members=members;last_member_event=time.monotonic()
                    emit({'event':'alias_members','members':sorted(members)[:128],'members_count':len(members)})
            if (names_update_requested is not None and activated and guard_result is None
                and not feed_stop_sent and not cancellation.requested and pending_edit is None
                and guard_deadline-time.monotonic()>3):
                edit=names_update_requested()
                if edit is not None:
                    pending_edit=_names_edit(edit,spec['policy_name'])
                    if pending_edit['revision']!=names_revision:raise ValueError('stale policy edit revision')
                    feed.stdin.write((json.dumps({'op':'names',**pending_edit})+'\n').encode());feed.stdin.flush()
            if feed_reader.eof and feed_result is None:raise RuntimeError('feed exited without report')
            if feed_result is not None and (guard is None or guard_result is not None):break
            select.select([reader.pipe for reader in (feed_reader,guard_reader) if reader is not None and not reader.eof]
                          +(list(seed.readers()) if isinstance(seed,SeedQueries) else []),[],[],.02)
        else:raise TimeoutError('block trial supervisor deadline')
        out['restoration_verified']=feed_result.get('restoration_verified') is True
        out['no_matching_address']=_no_match(activated,guard_result)
        valid_feed=feed_result.get('state')=='complete' or named and feed_stop_sent and feed_result.get('state')=='cancelled'
        if (not (activated or cancellation.requested or out['no_matching_address']) or not valid_feed or not out['restoration_verified']
            or not feed_result.get('resources_released') or guard is not None and not out['rule_removed']):
            raise RuntimeError('combined block trial incomplete')
        out['state']='cancelled' if cancellation.requested else 'complete'
    except Exception as exc:
        out['state']='inspection_required';out['error']=type(exc).__name__
        out['error_at']=[{'function':frame.name,'line':frame.lineno} for frame in traceback.extract_tb(exc.__traceback__)[-3:]]
    finally:
        if isinstance(seed,SeedQueries):
            seed.close(cancelled=True);out['initial_lookups' if seed_kind=='initial' else 'latest_names_lookups']=seed.status()
        elif seed is not None:out['initial_lookups']=seed
        # Never terminate the separate DNS rollback worker. Fencing its feed
        # coordinator causes that worker to restore the original hook itself.
        stopped=True
        for name,child,fence,reader in (('guard',guard,guard_fence,guard_reader),('feed',feed,feed_fence,feed_reader)):
            if fence is None:continue
            until=time.monotonic()+.5
            while not fence.inspect()['stopped'] and time.monotonic()<until:time.sleep(.01)
            status=fence.stop();out[name+'_fence']=status;stopped=stopped and status['stopped']
            if status['stopped']:
                # Drain final output even if process exit won the race.
                try:
                    for value in reader.take():
                        if name=='feed' and 'result' in value:feed_result=value['result']
                        elif name=='guard' and value.get('event')=='finished':guard_result=value
                except Exception:out[name+'_final_report_unavailable']=True
                for pipe in (child.stdin,child.stdout,child.stderr):
                    if pipe is not None and not pipe.closed:pipe.close()
        try:
            if guard_fence is not None and not out['guard_fence']['stopped']:raise RuntimeError('rule writer not fenced')
            if expected is not None:
                until=time.monotonic()+2
                while True:
                    try:out['rule_cleanup']=rule.disarm(expected);break
                    except ReloadBusy:
                        if time.monotonic()>=until:raise
                        time.sleep(.02)
                out['rule_removed']=out['rule_cleanup']['removed']
            if registered:
                from .registeredcleanup import finish_owned_session
                out['membership_cleanup']=finish_owned_session(registered_authority,membership_gate,
                    directory=Path(gate_path).parent,reload_lock_path=reload_lock_path,config_lock_path='/tmp/config.lock',
                    writers_stopped=stopped)
            out['resources_released']=stopped and out['rule_removed'] and (not registered or out['membership_cleanup']['empty_verified'])
        except Exception as exc:out['cleanup_error']=type(exc).__name__;out['state']='inspection_required'
        rule.close()
        if table is not None:table.close()
        out['feed_result'],out['guard_result']=feed_result,guard_result
        if out['state'] in ('complete','cancelled') and not out['resources_released']:out['state']='inspection_required'
    return out


def _feed():
    """One root supervisor owns this worker and its fresh borrowed table."""
    raw=sys.stdin.buffer.readline(32769)
    if len(raw)>32768 or not raw.endswith(b'\n'):raise ValueError('bounded feed request required')
    value=json.loads(raw);native=writer=member=None
    from .pfwriter import LeaseTableWriter
    from .indexedproofs import IndexedProofLedger
    from .leases import Policy
    from .trialfeed import TrialFeed
    from .trialservice import run as run_feed
    try:
        sustained=value.get('sustained',False)
        if type(sustained) is not bool:raise ValueError('explicit sustained feed flag required')
        native=NativePFTables('',(value['table'],),writable=True,max_members=4096 if sustained else 20000);native.enroll({value['table']:set()})
        if 'membership_gate' in value:
            from .membershipgate import MembershipGate
            member=MembershipGate(value['membership_gate'])
        writer=LeaseTableWriter(IndexedProofLedger([Policy(value['table'][3:],tuple(value['names']))]),native,
            reload_lock_path=value['reload_lock_path'],membership_gate=member)
        feed=TrialFeed(writer,table_use='supervised_block_trial',supervisor_pid=os.getppid())
        commands=_FeedCommands(_Reader(sys.stdin.buffer),feed,value['table'][3:],
            lambda event:print(json.dumps({'event':event}),flush=True))
        result=run_feed(value['target'],feed=feed,emit=lambda event:print(json.dumps({'event':event}),flush=True),
                        cancel_requested=(lambda:commands.poll() or member is not None and not member.available()) if sustained else None,
                        supervised_health=sustained)
        print(json.dumps({'result':result}),flush=True)
    finally:
        if writer is not None:writer.close()
        if native is not None:native.close()
        if member is not None:member.close()


if __name__=='__main__':
    if sys.argv[1:]!=['--feed']:raise ValueError('only explicit owned feed child entrypoint supported')
    _feed()
