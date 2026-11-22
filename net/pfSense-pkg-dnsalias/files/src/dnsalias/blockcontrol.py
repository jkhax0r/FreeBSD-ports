"""Inactive local UI control for one independently prepared short block trial.

The caller qualifies source/interface/order, creates and owns resources, then
supplies that fixed scope. Named sessions additionally accept up to16 revisions
of their name list; table identity, source, ports and deadlines remain fixed.
Requests cannot supply paths, executable commands or deadlines. This module never
starts processes, writes rules, changes DNS, or installs a service. The owner
must keep polling and connect cancellation to blockservice.run; the existing
independent expiry/rollback workers remain responsible for lost supervisors.

The endpoint is a private local Unix stream socket, never a network listener.
The native web page must authenticate and validate CSRF BEFORE sending changes.
"""
import hmac
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import time

from .blocktrial import validate as validate_rule
from .ipc import strict_pairs,finite_float,invalid_number
from .leases import dns_name,Policy
from .policystats import rule_ids


class PreparedTrial:
    """Single-use preview and cancellation latch, not policy authorization."""
    def __init__(self,rule,names,*,preview_seconds=60,block_seconds=5):
        self.rule=validate_rule(rule)
        if type(names) not in (list,tuple) or not 1<=len(names)<=8:raise ValueError('bounded exact names required')
        self.names=(Policy(self.rule['policy_name'],tuple(names)).patterns if 'policy_name' in self.rule
                    else tuple(dns_name(name) for name in names))
        if len(set(self.names))!=len(self.names):raise ValueError('unique exact names required')
        if type(preview_seconds) is not int or not 1<=preview_seconds<=120:raise ValueError('bounded preview lifetime required')
        self.token=secrets.token_hex(16);self.deadline=time.monotonic()+preview_seconds
        self.expires_utc=time.time()+preview_seconds
        self.state='prepared';self.cancelled=False;self.started=False
        self.activated=False;self.rule_removed=False;self.restored=False;self.released=False
        self.last_event=None;self.error=None
        if (block_seconds is None and 'policy_name' not in self.rule or block_seconds is not None
            and (type(block_seconds) is not int or (block_seconds!=5 and ('policy_name' not in self.rule or not 60<=block_seconds<=3600)))):
            raise ValueError('explicit named policy duration or until-stopped operation required')
        self.block_seconds=block_seconds
        self.members=[];self.members_count=0;self.members_observed_utc=None;self.no_match=False
        self.rule_counters=None;self.end_reason=None;self.history_recorded=None
        self.initial_names=self.names;self.names_revision=0;self.pending_names=None;self.names_dispatched=False
        self.registered_alias=False

    def _expire(self):
        if self.state in ('prepared','queued') and time.monotonic()>=self.deadline:self.state='expired'

    def snapshot(self):
        self._expire()
        return {'format':'dnsalias-trial-control-1','token':self.token,'state':self.state,
            'client':self.rule['client'],'interface':self.rule['interface'],'port':self.rule['port'],
            'protocol':'tcp/udp' if self.rule['port']=='web' else 'tcp','names':list(self.names),'include_subdomains':any(n.startswith('*.') for n in self.names),
            'block_seconds':self.block_seconds,'independent_rule_seconds':None if self.block_seconds is None else self.block_seconds+5,'preview_expires_utc':self.expires_utc,
            'started':self.started,'cancel_requested':self.cancelled,'rule_activated':self.activated,
            'rule_removed':self.rule_removed,'restoration_verified':self.restored,
            'resources_released':self.released,'last_event':self.last_event,'error':self.error,
            'traffic_verified':False,'shared_ip_impact':True,'table':self.rule['table'],
            'policy_name':self.rule.get('policy_name'),'duration_seconds':None if self.block_seconds is None else self.block_seconds+15,
            'names_revision':self.names_revision,'names_pending':None if self.pending_names is None else list(self.pending_names),
            'registered_alias':self.registered_alias,
            'members':list(self.members),'members_count':self.members_count,
            'members_observed_utc':self.members_observed_utc,'no_matching_address':self.no_match,
            'rule_trackers':rule_ids(self.rule),'rule_counters':self.rule_counters,'end_reason':self.end_reason,'history_recorded':self.history_recorded}

    def request(self,value):
        if type(value) is not dict:raise ValueError('request object required')
        operation=value.get('op')
        if operation=='status' and set(value)=={'op'}:return self.snapshot()
        if operation=='names':
            if (set(value)!={'op','token','revision','names'} or type(value['token']) is not str
                or len(value['token'])!=32 or not value['token'].isascii() or not hmac.compare_digest(value['token'],self.token)
                or type(value['revision']) is not int or value['revision']!=self.names_revision
                or self.names_revision>=16 or self.state!='running' or not self.activated
                or self.cancelled or self.rule_removed or 'policy_name' not in self.rule
                or type(value['names']) is not list or not 1<=len(value['names'])<=8
                or any(type(n) is not str for n in value['names'])):
                raise ValueError('fresh active named-policy edit required')
            names=Policy(self.rule['policy_name'],tuple(value['names'])).patterns
            if len(set(names))!=len(names):raise ValueError('distinct names required')
            if self.pending_names is not None:
                if names!=self.pending_names:raise ValueError('refresh the pending edit before another change')
            elif names!=self.names:self.pending_names=names;self.names_dispatched=False
            return self.snapshot()
        if (operation not in ('start','undo') or set(value)!={'op','token'}
            or type(value['token']) is not str or len(value['token'])!=32 or not value['token'].isascii()
            or not hmac.compare_digest(value['token'],self.token)):
            raise ValueError('exact prepared trial request required')
        self._expire()
        if operation=='start':
            if self.state=='expired':raise ValueError('preview expired')
            if self.state=='prepared':self.state='queued'
            # Duplicate or late start is a status read. Never restart a consumed
            # operation, revive a cancelled preview, or extend its deadline.
        else:
            if self.state in ('prepared','queued'):
                self.cancelled=True;self.state='cancelled'
            elif self.state in ('running','cancelling'):
                self.cancelled=True;self.state='cancelling'
        return self.snapshot()

    def begin(self):
        """Owner consumes a queued request once, immediately before preflight."""
        self._expire()
        if self.state!='queued' or self.started:return False
        self.started=True;self.state='running';return True

    def take_names_update(self):
        """Dispatch once; acknowledgement, never queue acceptance, changes names."""
        if self.pending_names is None or self.names_dispatched or self.cancelled:return None
        self.names_dispatched=True
        return {'revision':self.names_revision,'names':list(self.pending_names)}

    def event(self,value):
        if not self.started or self.state not in ('running','cancelling'):raise ValueError('running trial required')
        name=value.get('event') if type(value) is dict else None
        if name not in ('feed_started','rollback_ready','hook_phase','feed_ready','block_active','alias_members','rule_counters','block_removed','undo_requested','names_updated'):
            raise ValueError('known supervisor event required')
        self.last_event=name
        if name=='names_updated':
            if (self.pending_names is None or not self.names_dispatched
                or value.get('revision')!=self.names_revision+1
                or value.get('names')!=list(self.pending_names)):
                raise ValueError('exact pending name edit acknowledgement required')
            self.names=self.pending_names;self.pending_names=None
            self.names_revision+=1;self.names_dispatched=False
        if name in ('block_active','alias_members'):
            if name=='block_active':self.activated=True
            if 'members' in value:
                members=value['members'];count=value.get('members_count',len(members))
                if type(members) is not list or len(members)>128 or type(count) is not int or not len(members)<=count<=100000:
                    raise ValueError('bounded membership snapshot required')
                members=[str(ipaddress.ip_address(ip)) for ip in members]
                self.members=members;self.members_count=count;self.members_observed_utc=time.time()
        if name=='rule_counters':
            counters=value.get('counters')
            if (type(counters) is not dict or set(counters)!={'rule_trackers','packets','bytes','observed_utc'}
                or counters['rule_trackers']!=rule_ids(self.rule)
                or any(type(counters[k]) is not int or not 0<=counters[k]<2**65 for k in ('packets','bytes'))
                or type(counters['observed_utc']) not in (int,float) or not 0<=time.time()-counters['observed_utc']<=5):
                raise ValueError('qualified fresh exact-rule counters required')
            self.rule_counters=dict(counters)
        if name=='block_removed':self.rule_removed=True;self.end_reason=value.get('reason')
        if name=='undo_requested':self.cancelled=True;self.state='cancelling'

    def finish(self,result):
        if not self.started or self.state not in ('running','cancelling'):raise ValueError('single running trial result required')
        if (type(result) is not dict or result.get('format')!='dnsalias-short-block-trial-1'
            or result.get('rule')!=self.rule or result.get('names') not in (self.initial_names,list(self.initial_names))):
            raise ValueError('matching supervisor result required')
        # Only independently reported completion clears the pending restoration
        # indicator. A removed rule alone does not mean DNS has been restored.
        self.activated=result.get('rule_activated') is True
        self.rule_removed=result.get('rule_removed') is True
        self.restored=result.get('restoration_verified') is True
        self.released=result.get('resources_released') is True
        self.no_match=result.get('no_matching_address') is True
        self.state=result.get('state') if (result.get('state') in ('complete','cancelled')
            and self.rule_removed and self.restored and self.released and result.get('error') is None) else 'inspection_required'
        self.cancelled=self.cancelled or result.get('cancel_requested') is True
        self.pending_names=None
        self.error=None if self.state!='inspection_required' else 'Trial requires inspection'
        return self.snapshot()


class ControlSocket:
    """Bounded nonblocking endpoint polled by the single owning supervisor."""
    NAME='control.sock'
    def __init__(self,directory,trial):
        if os.name!='posix' or not hasattr(os,'O_NOFOLLOW'):raise ValueError('native owned socket required')
        from .feedcontrol import PreparedObservation
        if type(trial) not in (PreparedTrial,PreparedObservation):raise ValueError('explicit prepared operation required')
        self.directory=Path(directory);self.path=self.directory/self.NAME;self.trial=trial
        if not self.path.is_absolute() or '..' in self.path.parts or len(os.fsencode(self.path))>103:raise ValueError('short explicit absolute socket path required')
        self.uid=os.geteuid();self.fd=None;self.listener=None;self.identity=None;self.peers={};self.closed=False
        try:
            self.fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.directory_identity=self._directory()
            try:os.stat(self.NAME,dir_fd=self.fd,follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise FileExistsError('existing control endpoint requires inspection')
            self.listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            self.listener.setblocking(False);self.listener.bind(str(self.path))
            own=os.stat(self.NAME,dir_fd=self.fd,follow_symlinks=False)
            self.identity=(own.st_dev,own.st_ino)
            os.chmod(self.NAME,0o600,dir_fd=self.fd,follow_symlinks=False)
            self._check();self.listener.listen(4)
        except Exception:self.close(remove=False);raise

    def _directory(self):
        own=os.fstat(self.fd);named=os.stat(self.directory,follow_symlinks=False)
        if any(not stat.S_ISDIR(s.st_mode) or s.st_uid!=self.uid or stat.S_IMODE(s.st_mode)!=0o700 for s in (own,named)):
            raise ValueError('private owned control directory required')
        identity=own.st_dev,own.st_ino
        if identity!=(named.st_dev,named.st_ino) or getattr(self,'directory_identity',identity)!=identity:
            raise ValueError('control directory changed')
        return identity

    def _check(self):
        self._directory();own=os.stat(self.NAME,dir_fd=self.fd,follow_symlinks=False)
        if (not stat.S_ISSOCK(own.st_mode) or own.st_uid!=self.uid or stat.S_IMODE(own.st_mode)!=0o600
            or own.st_nlink!=1 or (own.st_dev,own.st_ino)!=self.identity):raise ValueError('control socket ownership changed')

    def poll(self):
        if self.closed:raise ValueError('control endpoint closed')
        self._check();now=time.monotonic()
        # At most four peers and one 2KiB request per peer. Partial readers/writers
        # expire after one second and cannot hold the supervisor or DNS path.
        for _ in range(4-len(self.peers)):
            try:peer,_=self.listener.accept()
            except BlockingIOError:break
            peer.setblocking(False);self.peers[peer]={'input':b'','output':None,'deadline':now+1}
        for peer,state in list(self.peers.items()):
            try:
                if now>=state['deadline']:raise ValueError('control peer timeout')
                if state['output'] is None:
                    try:part=peer.recv(4097-len(state['input']))
                    except BlockingIOError:continue
                    if not part:raise ValueError('control peer closed')
                    state['input']+=part
                    if len(state['input'])>4096:raise ValueError('control request bound')
                    if b'\n' not in state['input']:continue
                    line,rest=state['input'].split(b'\n',1)
                    if rest:raise ValueError('single control request required')
                    try:
                        value=json.loads(line,object_pairs_hook=strict_pairs,parse_float=finite_float,parse_constant=invalid_number)
                        result={'ok':True,'trial':self.trial.request(value)}
                    except (ValueError,TypeError,RecursionError):result={'ok':False,'error':'Request refused'}
                    state['output']=(json.dumps(result,separators=(',',':'),allow_nan=False)+'\n').encode()
                    if len(state['output'])>16384:raise ValueError('control reply bound')
                try:sent=peer.send(state['output'])
                except BlockingIOError:continue
                if sent<=0:raise ValueError('control send ended')
                state['output']=state['output'][sent:]
                if not state['output']:self._drop(peer)
            except (OSError,ValueError):self._drop(peer)

    def cancellation(self):
        self.poll();return self.trial.cancelled

    def _drop(self,peer):
        self.peers.pop(peer,None);peer.close()

    def close(self,*,remove=True):
        if self.closed:return
        try:
            if remove and self.identity is not None:
                self._check();os.unlink(self.NAME,dir_fd=self.fd)
        finally:
            for peer in list(self.peers):self._drop(peer)
            if self.listener is not None:self.listener.close()
            if self.fd is not None:os.close(self.fd);self.fd=None
            self.closed=True

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
