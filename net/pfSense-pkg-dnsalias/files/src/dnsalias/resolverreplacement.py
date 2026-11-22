"""Bounded, read-only qualification of a replacement resolver process.

The caller must first observe the old
kernel process exit and freeze the source identities from its live ownership
lifetime. This worker performs no reload, hook write, lease update or adoption.
Its result is only input to the independent hook-worker handoff and a fresh
reply-generation enrollment; a TLS status response is never enough by itself.

All watches and file descriptors used here belong to this thread. Slow TLS or
source reads therefore need not stall the caller's lease expiry/watchdog loop.
"""
import copy
import threading
import time

from .processwatch import ProcessLifetimeWatch
from .runtimecontrol import RuntimeControl,RuntimeControlError,load_credentials,status_value
from .sourceaudit import SourceAudit,SourceSpec


def source_identity(audit):
    """Freeze already-inspected metadata; never recapture or accept new files."""
    if not isinstance(audit,SourceAudit) or audit.state!='qualified':
        raise ValueError('live qualified source ownership required')
    audit.audit()
    return {
        'hashes':dict(audit.hashes),
        'files':{spec.name:tuple(metadata) for spec,_,_,_,metadata in audit.files},
        'directories':{path:tuple(row[3]) for path,row in audit.directories.items()},
    }


def unchanged_replacement_sources(prior,observed):
    """Permit only timestamp renewal of the same root-owned config inode.

    pfSense rewrites unbound.conf during an ordinary DHCP save, even when its
    bytes are identical. This comparison is used only after confirmed resolver
    exit, alongside fresh TLS/runtime qualification. Code and directory
    identities, file ownership, inode and every content hash stay exact.
    """
    return _unchanged_sources(prior,observed,{0})


def unchanged_reader_sources(prior, observed, specs, uid, gid):
    """The authenticated same-process reader may also renew its pinned pfSense config."""
    owners = {0}
    for spec in specs:
        if (spec.name == 'resolver_config' and spec.path == '/var/unbound/unbound.conf'
                and (spec.uid, spec.gid) == (uid, gid)
                and prior['files'][spec.name][2:5] == (uid, gid, 0o644)):
            owners.add(uid)
    return _unchanged_sources(prior,observed,owners)


def _unchanged_sources(prior,observed,config_owners):
    if observed==prior:return True
    if (observed['hashes']!=prior['hashes'] or observed['directories']!=prior['directories']
        or observed['files'].keys()!=prior['files'].keys()):return False
    for name,before in prior['files'].items():
        after=observed['files'][name]
        if after==before:continue
        if (name!='resolver_config' or len(before)!=9 or len(after)!=9
            or before[2] not in config_owners or before[:7]!=after[:7]):return False
    return True


class ResolverReplacement:
    POLL_SECONDS=.25

    def __init__(self,*,old_watch,specs,ancestors,identity,snapshot,
                 credential_directory,credential_uid,credential_gid,credential_id,
                 control_port,budget_seconds=12):
        if (not isinstance(old_watch,ProcessLifetimeWatch) or old_watch.alive()
            or old_watch.state!='exited'):
            raise ValueError('confirmed old resolver exit required')
        if type(budget_seconds) not in (int,float) or not .1<=budget_seconds<=30:
            raise ValueError('bounded read-only replacement search required')
        if (type(specs) not in (tuple,list) or not specs or len(specs)>SourceAudit.MAX_FILES
            or any(not isinstance(spec,SourceSpec) for spec in specs)
            or len({s.name for s in specs})!=len(specs)):
            raise ValueError('complete distinct source specifications required')
        names={s.name for s in specs}
        if (type(identity) is not dict or set(identity)!= {'hashes','files','directories'}
            or set(identity['hashes'])!=names or set(identity['files'])!=names
            or not identity['directories']):
            raise ValueError('exact prior source identities required')
        if (type(snapshot) is not dict or type(snapshot.get('settings')) is not dict
            or snapshot.get('versions',{}).get('unbound')!='1.26.1'):
            raise ValueError('prior qualified resolver settings required')
        if (type(credential_id) is not str or len(credential_id)!=64
            or type(control_port) is not int or not 1<=control_port<=65535):
            raise ValueError('prior credential identity and control port required')
        self.old_pid=old_watch.pid;self.specs=tuple(specs);self.ancestors=tuple(ancestors)
        self.identity=copy.deepcopy(identity);self.snapshot=copy.deepcopy(snapshot)
        self.credential_directory=credential_directory
        self.uid,self.gid=credential_uid,credential_gid;self.credential_id=credential_id;self.port=control_port
        self.budget=budget_seconds;self.cancelled=threading.Event();self.thread=None
        self.result={'state':'new','pid':None,'error':None,'status_reads':0,
            'runtime_attempts':0,'runtime_transient_failures':0}

    def _credentials(self):
        value=load_credentials(self.credential_directory,expected_uid=self.uid,expected_gid=self.gid)
        if value['credential_id']!=self.credential_id:
            raise ValueError('replacement control credentials changed')
        return value

    def _remaining(self,deadline):
        if self.cancelled.is_set():raise InterruptedError('replacement search cancelled')
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('replacement search deadline')
        return remaining

    def _capture_runtime(self,control,watch,sources,deadline,result):
        # A new resolver can answer status before a later control connection
        # is ready. Retry only the same read-only transport unavailability
        # already accepted by status discovery, inside the original deadline.
        # Each new attempt rechecks source/credential/process ownership. A
        # pin, response, setting or source failure remains final.
        while True:
            self._remaining(deadline);self._credentials();sources.audit()
            if not watch.alive():raise ValueError('replacement process lifetime ended')
            result['runtime_attempts']+=1
            try:return control.capture(watch,budget_seconds=min(3,self._remaining(deadline)))
            except RuntimeControlError as exc:
                if not isinstance(exc.__cause__,(TimeoutError,ConnectionRefusedError,ConnectionResetError)):raise
                sources.audit();self._credentials()
                if not watch.alive():raise ValueError('replacement process lifetime ended')
                result['runtime_transient_failures']+=1
                self.cancelled.wait(min(self.POLL_SECONDS,self._remaining(deadline)))

    def _run(self):
        result={'state':'searching','pid':None,'error':None,'status_reads':0,'runtime_attempts':0,'runtime_transient_failures':0}
        deadline=time.monotonic()+self.budget;self.result=dict(result)
        try:
            self._remaining(deadline)
            credentials=self._credentials()
            control=RuntimeControl(credentials['context'],address='127.0.0.1',port=self.port,
                                   server_certificate_sha256=credentials['server_certificate_sha256'])
            while True:
                remaining=self._remaining(deadline);result['status_reads']+=1
                try:
                    found=status_value(control._read(None,time.monotonic()+min(.2,remaining)))
                except RuntimeControlError as exc:
                    # Retry only read-only unavailability. Pin/certificate,
                    # malformed response and configuration failures are final.
                    if not isinstance(exc.__cause__,(TimeoutError,ConnectionRefusedError,ConnectionResetError)):
                        raise
                    self.cancelled.wait(min(self.POLL_SECONDS,self._remaining(deadline)))
                    continue
                if found['pid']==self.old_pid:
                    raise ValueError('retired resolver PID cannot be adopted')
                break
            self._remaining(deadline)
            with ProcessLifetimeWatch(found['pid']) as watch,SourceAudit(self.specs,ancestor_uids=self.ancestors) as sources:
                observed=source_identity(sources)
                if not unchanged_replacement_sources(self.identity,observed):
                    # Report labels only, never source contents or credentials.
                    # A native reconfiguration and a foreign hook must remain
                    # distinguishable without weakening either refusal.
                    result['source_changes']={
                        'content':sorted(name for name in observed['hashes'] if observed['hashes'][name]!=self.identity['hashes'][name]),
                        'metadata':sorted(name for name in observed['files'] if observed['files'][name]!=self.identity['files'][name]),
                        'directories_changed':observed['directories']!=self.identity['directories'],
                    }
                    raise ValueError('replacement source bytes or metadata changed')
                if observed!=self.identity:
                    result['resolver_config_metadata']=list(observed['files']['resolver_config'])
                # A newly restarted resolver may still be loading policy data.
                # Keep the overall replacement deadline and all source/TLS
                # checks. Each complete read-only sweep gets at most three
                # seconds; known transport failures may retry only inside
                # the same overall replacement deadline.
                capture_started=time.monotonic()
                try:runtime=self._capture_runtime(control,watch,sources,deadline,result)
                finally:result['runtime_capture_seconds']=time.monotonic()-capture_started
                if (runtime['status']['pid']!=found['pid']
                    or runtime['status']['version']!=self.snapshot['versions']['unbound']
                    or runtime['settings']!=self.snapshot['settings']):
                    raise ValueError('replacement runtime differs from qualified settings')
                self._credentials();sources.audit();self._remaining(deadline)
                if not watch.alive():raise ValueError('replacement process lifetime ended')
                result.update(state='qualified',pid=watch.pid,observed_monotonic=time.monotonic(),
                              sources_unchanged=observed==self.identity,source_bytes_unchanged=True,
                              credentials_unchanged=True,runtime_unchanged=True)
        except InterruptedError:
            result.update(state='cancelled',pid=None,error=None)
        except TimeoutError:
            result.update(state='unavailable',pid=None,error='replacement_search_deadline')
        except Exception as exc:
            result.update(state='failed',pid=None,error=type(exc).__name__+': '+str(exc)[:160])
        finally:
            # Publish a scalar copy only. Native descriptors never cross into
            # the owner loop, which must enroll its own fresh watch.
            self.result=dict(result)

    def start(self):
        if self.thread is not None or self.result['state']!='new':
            raise ValueError('replacement search is single-use')
        self.thread=threading.Thread(target=self._run,name='dnsalias-resolver-replacement',daemon=True)
        self.thread.start()

    def close(self,wait_seconds=0):
        if type(wait_seconds) not in (int,float) or not 0<=wait_seconds<=1:
            raise ValueError('bounded replacement-worker join required')
        self.cancelled.set()
        if self.thread is not None:self.thread.join(timeout=wait_seconds)
        return self.thread is None or not self.thread.is_alive()

    def status(self):
        return dict(self.result)|{'thread_alive':self.thread is not None and self.thread.is_alive(),
                                 'hook_changed':False,'reload_requested':False,'generation_enrolled':False}
