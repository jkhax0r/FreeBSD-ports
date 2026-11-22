"""Inactive, single-use short block-rule trial in an exclusively owned anchor.

Caller owns the empty anchor, unique root table, private gate, table writer and
supervision. This component neither creates those resources nor registers a
production rule, alias, startup hook or persistent configuration. It never adds
a pass rule, kills states, empties tables, or adopts another rule. A matching
destination IP is shared across domains; this is not exact hostname filtering.

The separate worker must be directly supervised. It removes its rule on owner
loss, input EOF, explicit undo or deadline. Its parent must fence a failed worker
before exact cleanup. All pfctl children inherit both locks, preventing cleanup
from overtaking a delayed activation if the worker is killed. A still-running
kernel operation, foreign edit, or busy/changed lock is reported as unresolved;
there is no blind flush, mutation retry or claim of guaranteed kernel recovery.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess
import time
import traceback

from .processwatch import ProcessLifetimeWatch
from .policystats import rule_ids,counters
from .reloadlock import SharedReloadLock,ExclusiveConfigLock,ReloadBusy


def validate(value):
    fields={'token','anchor','table','client','interface','port'}
    if type(value) is not dict or set(value) not in (fields,fields|{'policy_name'}):
        raise ValueError('exact block-trial fields required')
    token=value['token']
    if type(token) is not str or not re.fullmatch('[0-9a-f]{16}',token):raise ValueError('unique trial token required')
    if value['anchor'] not in ('dnsalias_trial_'+token,'userrules/dnsalias_trial_'+token):
        raise ValueError('owned trial anchor required')
    if 'policy_name' in value:
        name=value['policy_name']
        if type(name) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,22}',name) or name.startswith(('mvp_','seed')):
            raise ValueError('bounded distinct policy name required')
        if value['table']!='da_'+name:raise ValueError('named policy table required')
    elif value['table']!='da_mvp_'+token[:12]:raise ValueError('owned trial table required')
    if type(value['client']) is not str:raise ValueError('single client IP required')
    address=ipaddress.ip_address(value['client'])
    if str(address)!=value['client'] or address.is_multicast or address.is_unspecified or address.is_loopback:
        raise ValueError('canonical unicast client IP required')
    if type(value['interface']) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_.]{0,15}',value['interface']):
        raise ValueError('single native interface required')
    if not (type(value['port']) is int and value['port'] in (80,443)
            or 'policy_name' in value and value['port']=='web'):
        raise ValueError('explicit web port or named bounded web traffic scope required')
    return dict(value)


def render(value):
    value=validate(value)
    family='inet6' if ':' in value['client'] else 'inet'
    scopes=(('tcp',80),('tcp',443),('udp',80),('udp',443)) if value['port']=='web' else (('tcp',value['port']),)
    identifiers=rule_ids(value)
    return ''.join('block return in log quick on '+value['interface']+' '+family+' proto '+protocol+' from '+value['client']+
        ' to <'+value['table']+'> port = '+str(port)+(' ridentifier '+identifiers[i] if identifiers else '')+
        ' label "dnsalias_trial_'+value['token']+'"\n' for i,(protocol,port) in enumerate(scopes))


def gate_identity(path):
    path=Path(path);parent=path.parent.lstat();item=path.lstat()
    if (not path.is_absolute() or not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0
        or stat.S_IMODE(parent.st_mode)!=0o700 or not stat.S_ISREG(item.st_mode)
        or item.st_uid!=0 or item.st_nlink!=1 or stat.S_IMODE(item.st_mode)!=0o600):
        raise ValueError('owned private gate metadata changed')
    return item.st_dev,item.st_ino


class ScopedBlockRule:
    """One activation and one exact disarm; caller serializes all operations."""
    def __init__(self,value,*,gate_path,gate_inode,reload_lock_path):
        self.spec=validate(value);self.body=render(value);self.expected=None
        if type(gate_inode) not in (tuple,list) or len(gate_inode)!=2 or any(type(n) is not int for n in gate_inode):
            raise ValueError('fresh owned gate identity required')
        self.gate_path=Path(gate_path);self.gate_inode=tuple(gate_inode)
        self.gate=ExclusiveConfigLock(gate_path);self.reload=SharedReloadLock(reload_lock_path)
        self.activation_attempted=False;self.removal_attempted=False;self.prepared=False

    def _check_gate(self):
        if gate_identity(self.gate_path)!=self.gate_inode:raise ValueError('private gate replaced')

    def _command(self,args,body=None):
        # These are fixed argv from below; no shell or caller-supplied commands.
        # Inheritance keeps an outstanding pfctl operation inside the same
        # serialization boundary even if this worker is abruptly terminated.
        if not self.gate.valid() or not self.reload.valid():raise ValueError('rule locks not held')
        result=subprocess.run(['/sbin/pfctl',*args],input=body,text=True,capture_output=True,
            timeout=1,pass_fds=(self.gate.fd,self.reload.fd))
        absent=(args in (['-a',self.spec['anchor'],'-s','Anchors'],['-a',self.spec['anchor'],'-s','Tables'])
            and result.returncode==1 and result.stdout=='' and result.stderr=='pfctl: Anchor does not exist.\n')
        if (result.returncode and not absent) or len(result.stdout)>65536 or len(result.stderr)>4096:
            raise RuntimeError('bounded native rule operation failed')
        if not self.gate.valid() or not self.reload.valid():raise ValueError('rule lock changed during operation')
        return result.stdout

    def _scope(self):
        args=['-a',self.spec['anchor']]
        if any(self._command(args+option).strip() for option in
               (['-sn'],['-s','Anchors'],['-s','Tables'])):
            raise ValueError('trial anchor has foreign objects')
        return self._command(args+['-sr'])

    def _compiled(self):
        text=self._command(['-a',self.spec['anchor'],'-n','-v','-f','-'],self.body)
        lines=text.splitlines();expected_count=4 if self.spec['port']=='web' else 1
        if len(lines)!=expected_count or any(not line.startswith('block ') or '<'+self.spec['table']+'>' not in line
                or 'label "dnsalias_trial_'+self.spec['token']+'"' not in line for line in lines):
            raise ValueError('native block rule preview unavailable')
        return text

    def prepare(self):
        if self.prepared:raise ValueError('rule preparation is single-use')
        self._check_gate()
        with self.gate,self.reload:
            self._check_gate()
            if self._scope().strip():raise ValueError('trial rule namespace is not empty')
            if self.spec['table'] not in self._command(['-s','Tables']).split():
                raise ValueError('caller-owned root table missing')
            self.expected=self._compiled();self.prepared=True
            return self.expected

    def activate(self,*,deadline,alive):
        if not self.prepared or self.activation_attempted or self.removal_attempted:
            raise ValueError('prepared single-use activation required')
        self._check_gate()
        with self.gate,self.reload:
            self._check_gate()
            if self._scope().strip():raise ValueError('trial namespace changed before activation')
            if self.spec['table'] not in self._command(['-s','Tables']).split():
                raise ValueError('root table missing before activation')
            # Last authorization check is inside both locks. A queued command
            # never gets a fresh deadline when it eventually acquires the gate.
            maximum=86400 if 'policy_name' in self.spec else 30
            if type(deadline) not in (int,float) or not time.monotonic()<deadline<=time.monotonic()+maximum or not alive():
                raise ValueError('trial activation expired or owner ended')
            self.activation_attempted=True
            self._command(['-a',self.spec['anchor'],'-f','-'],self.body)
            if self._scope()!=self.expected:raise RuntimeError('rule activation outcome requires inspection')
            return {'active':True,'canonical_rule':self.expected}

    def counters(self):
        self._check_gate()
        with self.gate,self.reload:
            self._check_gate()
            value=counters(self._command(['-a',self.spec['anchor'],'-vvsr']),self.expected,rule_ids(self.spec))
            return None if value is None else value|{'observed_utc':time.time()}

    def disarm(self,expected):
        if type(expected) is not str or not expected or len(expected)>2048:raise ValueError('recorded rule preview required')
        if self.removal_attempted:raise ValueError('rule removal cannot be retried')
        self._check_gate()
        with self.gate,self.reload:
            self._check_gate();current=self._scope()
            if not current.strip():return {'removed':True,'already_absent':True}
            if current!=expected or self._compiled()!=expected:raise ValueError('changed rule preserved')
            self.removal_attempted=True
            self._command(['-a',self.spec['anchor'],'-f','-'],'')
            if self._scope().strip():raise RuntimeError('rule removal outcome requires inspection')
            return {'removed':True,'already_absent':False}

    def close(self):
        self.gate.close();self.reload.close()


def worker(plan,*,control_fd=0,emit=None):
    """Run detached under a directly owning parent; no self-installation."""
    required={'rule','gate_path','gate_inode','reload_lock_path','parent_pid','deadline'}
    if type(plan) is not dict or not required<=set(plan) or set(plan)-required-{'dependency_pid'}:
        raise ValueError('exact rule worker plan required')
    if 'dependency_pid' in plan and (type(plan['dependency_pid']) is not int or not 0<plan['dependency_pid']<2**31):
        raise ValueError('explicit dependency process required')
    deadline=plan['deadline']
    spec=validate(plan['rule']);maximum=86400 if 'policy_name' in spec else 30
    if (type(deadline) not in (int,float) or not time.monotonic()<deadline<=time.monotonic()+maximum
        or type(plan['parent_pid']) is not int or plan['parent_pid']!=os.getppid()):
        raise ValueError('live direct parent and bounded original deadline required')
    emit=emit or (lambda value:print(json.dumps(value),flush=True))
    rule=ScopedBlockRule(plan['rule'],gate_path=plan['gate_path'],gate_inode=plan['gate_inode'],reload_lock_path=plan['reload_lock_path'])
    watch=ProcessLifetimeWatch(plan['parent_pid']);watches=[watch];expected=None;buffer=b''
    def alive():return all(item.alive() for item in watches)
    outcome={'active':False,'activated':False,'removed':False,'reason':None,'error':None};next_stats=0
    try:
        if 'dependency_pid' in plan:watches.append(ProcessLifetimeWatch(plan['dependency_pid']))
        expected=rule.prepare();emit({'event':'ready','canonical_rule':expected})
        while time.monotonic()<deadline and alive():
            if 'policy_name' in spec and outcome['active'] and time.monotonic()>=next_stats:
                next_stats=time.monotonic()+5
                try:sample=rule.counters()
                except ReloadBusy:next_stats=time.monotonic()+.5;continue
                if sample is None:outcome['reason']='rule_absent';break
                outcome['counters']=sample;emit({'event':'counters','counters':sample})
            ready,_,_=select.select([control_fd],[],[],min(.1,max(0,deadline-time.monotonic())))
            if not ready:continue
            chunk=os.read(control_fd,32)
            if not chunk:outcome['reason']='owner_pipe_closed';break
            buffer+=chunk
            if len(buffer)>32:raise ValueError('bounded rule command exceeded')
            if b'\n' not in buffer:continue
            command,buffer=buffer.split(b'\n',1)
            if buffer:raise ValueError('only one outstanding rule command permitted')
            if command==b'undo':outcome['reason']='undo';break
            if command!=b'activate' or outcome['active']:raise ValueError('unknown or repeated rule command')
            outcome.update(rule.activate(deadline=deadline,alive=alive));outcome['activated']=True;emit({'event':'active'})
        if outcome['reason'] is None:
            outcome['reason']='deadline' if time.monotonic()>=deadline else 'parent_ended' if not watch.alive() else 'dependency_ended'
    except Exception as exc:
        outcome['error']=type(exc).__name__
        outcome['error_at']=[{'function':f.name,'line':f.lineno} for f in traceback.extract_tb(exc.__traceback__)[-3:]]
    finally:
        try:
            if expected is not None:
                if 'policy_name' in spec and outcome['active']:
                    try:
                        sample=rule.counters()
                        if sample is not None:outcome['counters']=sample;emit({'event':'counters','counters':sample})
                    except Exception as exc:outcome['counter_error']=type(exc).__name__
                # A busy gate is a known unexecuted removal. Wait briefly for
                # the native reload or inherited outstanding child operation.
                until=time.monotonic()+2
                while True:
                    try:
                        outcome.update(rule.disarm(expected));outcome['active']=False;break
                    except ReloadBusy:
                        if time.monotonic()>=until:raise
                        time.sleep(.02)
        except Exception as exc:outcome['cleanup_error']=type(exc).__name__
        rule.close()
        for item in watches:item.close()
    emit({'event':'finished',**outcome});return outcome


if __name__=='__main__':
    # Root supervisor passes one bounded JSON line, then explicit commands on
    # the same pipe. Read without buffered IO that could swallow later bytes.
    data=bytearray()
    while len(data)<=4096:
        byte=os.read(0,1)
        if not byte:raise ValueError('worker plan missing')
        if byte==b'\n':break
        data.extend(byte)
    else:raise ValueError('worker plan too large')
    result=worker(json.loads(data))
    raise SystemExit(0 if result['removed'] and result['error'] is None else 1)
