"""Fresh capability donation, with PF qualification left in the owner loop.

One authenticated request is outstanding at a time. Source capture is off the
DNS loop and must match the original identities, metadata and content hashes.
Failure ends refresh for this resolver lifetime; no request is retransmitted.
"""
import re
import select
import threading
import time
from .sourceaudit import SourceAudit
from .processwatch import ProcessLifetimeWatch
from .changebarrier import CapabilityChangeBarrier
from .watchtransfer import send_source_watch
from .ipc import receive,send_observation
from .reloadlock import ReloadBusy


class RefreshDonor:
    def __init__(self,owner,sources,*,producer_pid,profile_id):
        if type(sources) is not SourceAudit or sources.state!='qualified':
            raise ValueError('original qualified sources required')
        self.owner=owner;self.pid=producer_pid;self.profile=profile_id
        self.specs=tuple(row[0] for row in sources.files);self.ancestors=sources.ancestor_uids
        self.hashes=dict(sources.hashes)
        self.metadata={row[0].name:row[4] for row in sources.files}
        self.directories={name:row[3] for name,row in sources.directories.items()}
        self.cancel=threading.Event();self.job=None;self.failure=None
        self.failure_stage=None;self.failure_errno=None
        self.sequence=0;self.completed=0
        self.thread=threading.Thread(target=self._run,name='dnsalias-watch-refresh',daemon=True)
        self.thread.start()

    def _check_request(self,request):
        fields={'watch_refresh','nonce','sequence','profile_id','resolver_generation','source_manifest'}
        if (type(request) is not dict or set(request)!=fields
            or request['watch_refresh']!=self.owner.token.hex()
            or request['profile_id']!=self.profile
            or request['resolver_generation']!=self.owner.enrolled_generation
            or request['source_manifest']!=self.owner.manifest_digest
            or type(request['sequence']) is not int or request['sequence']!=self.sequence+1
            or not 0<request['sequence']<2**31
            or type(request['nonce']) is not str or not re.fullmatch('[a-f0-9]{64}',request['nonce'])
            or request['nonce'] in ('0'*64,self.owner.token.hex())):
            raise ValueError('fresh exact reader request required')
        self.sequence=request['sequence']

    def _owner_permission(self,stage,deadline):
        job={'stage':stage,'deadline':deadline,'ready':threading.Event(),'granted':False}
        self.job=job
        while not job['ready'].wait(.01):
            if self.cancel.is_set() or time.monotonic()>=deadline:
                raise TimeoutError('owner qualification not completed')
        if self.cancel.is_set() or time.monotonic()>=deadline:
            raise TimeoutError('owner qualification not completed')
        if not job['granted']:
            raise ValueError('owner qualification refused')

    def _receive(self,deadline,watch):
        while time.monotonic()<deadline and not self.cancel.is_set() and watch.alive():
            if select.select([self.owner.donor.socket],[],[],min(.05,max(0,deadline-time.monotonic())))[0]:
                return receive(self.owner.donor.socket,expected_uid=self.owner.uid,expected_pid=self.pid)[0]
        raise TimeoutError('reader refresh receipt absent')

    def _capture(self):
        fresh=SourceAudit(list(self.specs),ancestor_uids=self.ancestors,budget_seconds=.5)
        if (fresh.hashes!=self.hashes or {row[0].name:row[4] for row in fresh.files}!=self.metadata
            or {name:row[3] for name,row in fresh.directories.items()}!=self.directories):
            fresh.close();raise ValueError('refresh cannot adopt changed DNS sources')
        return fresh

    def _run(self):
        stage='producer_watch'
        try:
            with ProcessLifetimeWatch(self.pid) as watch:
                while not self.cancel.is_set():
                    stage='request'
                    if not watch.alive():return
                    if not select.select([self.owner.donor.socket],[],[],.1)[0]:continue
                    request=receive(self.owner.donor.socket,expected_uid=self.owner.uid,expected_pid=self.pid)[0]
                    self._check_request(request);deadline=time.monotonic()+.9
                    stage='revoke'
                    self._owner_permission('revoke',deadline)
                    owner=self.owner
                    stage='source_capture'
                    with self._capture() as sources:
                        owner._lock_qualified()
                        if not owner.donor.healthy():raise ValueError('owned donor changed')
                        endpoint=str(owner.directory/'reader/replies.sock')
                        entries=[(owner.lock_fd,'file',CapabilityChangeBarrier.metadata(owner.lock_fd,'file'))]
                        entries.extend((fd,'file',wanted) for spec,parent,name,fd,wanted in sources.files)
                        entries.extend((fd,'directory',wanted) for parent,name,fd,wanted in sources.directories.values())
                        stage='donate'
                        digest=send_source_watch(owner.donor.socket,endpoint,entries,
                            token=bytes.fromhex(request['nonce']),restrict=owner.asset.module.watch_restrict)
                        stage='reader_receipt'
                        receipt=self._receive(deadline,watch)
                        expected={'watch_enrolled':request['nonce'],'profile_id':self.profile,
                                  'resolver_generation':owner.enrolled_generation,'source_manifest':digest}
                        if receipt!=expected:raise ValueError('fresh watch receipt differs')
                        # The sole PF owner audits tables under its reload lock.
                        # This worker never touches the lease ledger or PF.
                        stage='qualify'
                        self._owner_permission('qualify',deadline)
                        sources.audit(budget_seconds=.1);owner._lock_qualified();owner.page.audit()
                        if not watch.alive() or self.cancel.is_set() or time.monotonic()>=deadline:
                            raise ValueError('refresh lifetime ended')
                        commit=dict(expected);commit['watch_committed']=commit.pop('watch_enrolled')
                        stage='reader_commit'
                        if send_observation(owner.donor.socket,endpoint,commit)!='queued':
                            raise ValueError('fresh commit not sent; never retry')
                        owner.manifest_digest=digest;self.completed+=1
                        # Publication remains disabled until the owner observes
                        # this completed commit. Its next normal reply performs
                        # current PF synchronization before publishing a receipt.
                        stage='owner_commit'
                        self._owner_permission('committed',deadline)
        except Exception as exc:
            if not self.cancel.is_set() and self.failure is None:
                self.failure_stage=stage
                self.failure_errno=exc.errno if isinstance(exc,OSError) else None
                self.failure=type(exc).__name__

    def poll(self,session):
        """Only from the sole PF owner, after its normal receive/ACK work."""
        owner=self.owner
        if self.failure:
            owner.authority.invalidate();owner.state='disabled';owner.reason='refresh_'+self.failure
            return
        job=self.job
        if job is None or job['ready'].is_set():return
        if self.cancel.is_set() or time.monotonic()>=job['deadline']:
            job['ready'].set();return
        try:
            if job['stage']=='revoke':
                owner.authority.invalidate();owner.state='refreshing'
            elif job['stage']=='qualify':
                if not session.audit(deadline=min(job['deadline'],time.monotonic()+.04)):
                    raise ValueError('current table audit failed')
            elif job['stage']=='committed':owner.state='enrolled'
            else:raise ValueError('unknown refresh phase')
            job['granted']=True;job['ready'].set()
        except ReloadBusy:pass  # Known unexecuted; bounded by this same request.
        except Exception as exc:
            self.failure_stage=job['stage']
            self.failure=type(exc).__name__;owner.authority.invalidate()
            owner.state='disabled';owner.reason='refresh_'+self.failure;job['ready'].set()

    def close(self):
        self.cancel.set()
        if self.job is not None:self.job['ready'].set()
        self.thread.join(timeout=1.2)
        if self.thread.is_alive():raise RuntimeError('refresh donor still running; retain resources')

    def status(self):
        return {'completed':self.completed,'sequence':self.sequence,'failure':self.failure,
                'failure_stage':self.failure_stage,'failure_errno':self.failure_errno,
                'pending':bool(self.thread.is_alive() and self.job and not self.job['ready'].is_set())}
