"""Optional service-owned page and pre-reload notice donor. Off by default.

This closes resource/startup wiring, not external mutation coverage. Callers
must explicitly opt in only within a qualified isolated lifecycle test until
all relevant source and PF mutation paths have been covered.
"""
import os
import math
from pathlib import Path
import re
import select
import stat
import threading
import time
import uuid
from .confirmation import ConfirmationAuthority
from .confirmationpage import ConfirmationPage
from .nativeasset import NativeConfirmationAsset,NativeKeyAsset
from .replyendpoint import ReplyEndpoint
from .processwatch import ProcessLifetimeWatch
from .sourceaudit import SourceAudit,SourceSpec
from .watchtransfer import send_source_watch,_file
from .changebarrier import CapabilityChangeBarrier
from .ipc import receive,send_observation,RejectedMessage

COMPONENTS={'page':'confirmationpage.py','process_watch':'processwatch.py','key':'confirmationkey.py',
    'gate':'replygate.py','transport':'confirmationtransport.py','change_barrier':'changebarrier.py',
    'watch_transfer':'watchtransfer.py','watch_startup':'watchstartup.py'}


def identity(path):
    i=path.lstat()
    return i.st_dev,i.st_ino,i.st_uid,i.st_gid,stat.S_IMODE(i.st_mode),stat.S_IFMT(i.st_mode)


class ConfirmationOwner:
    @classmethod
    def create(cls,root,control_directory,settings,*,resolver_uid,resolver_gid,lock_path='/tmp/filter.lock',refresh=False,same_pid_reload=False):
        if os.geteuid()!=0:raise ValueError('root service owner required')
        if type(refresh) is not bool:raise ValueError('explicit refresh opt-in required')
        if type(same_pid_reload) is not bool:raise ValueError('explicit reader reload protocol required')
        self=cls();self.creator=os.getpid();self.state='preparing';self.reason=None
        self.refresh_enabled=refresh;self.refresh_donor=None
        self.page=self.asset=self.key_asset=self.donor=self.authority=None
        self.thread=None;self.cancel=threading.Event();self.cleanup_pid=None;self.cleanup_ready=False;self.cleanup_watch=None
        self.enrolled_generation=None;self.lock_fd=None;self.closed=False;self.sources={};self.source_specs=[]
        self.watch_counts=None;self.manifest_digest=None
        self.producer_pid=None;self.retired_generation=None;self.replacements=0
        self.retirement=None;self.pending_reload=None;self.pending_hello=None;self.reconfigurations=0;self.notice_rejected=0
        self.root=Path(root);self.settings=dict(settings);self.uid=resolver_uid;self.gid=resolver_gid
        self.directory=Path(control_directory)/('dcr-'+uuid.uuid4().hex)
        self.directory.mkdir(mode=0o750);os.chown(self.directory,0,resolver_gid);self.directory.chmod(0o750)
        self.identities={'directory':identity(self.directory)}
        try:
            self.asset=NativeConfirmationAsset.prepare(root,self.directory,settings,resolver_uid=resolver_uid,expected_directory=self.identities['directory'])
            if self.asset is None:raise ValueError('native confirmation component required for explicit opt-in')
            if type(getattr(self.asset.module,'WATCH_FD_ABI',None)) is not int or self.asset.module.WATCH_FD_ABI!=1:
                raise ValueError('native source-watch capability API required for explicit opt-in')
            self.key_asset=NativeKeyAsset.prepare(root,self.directory,settings,resolver_uid=resolver_uid,expected_directory=self.identities['directory'])
            self.page=ConfirmationPage.create(self.asset.module,self.directory,expected_directory=self.identities['directory'],ancestor_uids=(0,resolver_uid))
            self.authority=ConfirmationAuthority(self.asset.module,self.page.handle,available=self.available,
                answer_key=None if self.key_asset is None else self.key_asset.module.key)
            for name,uid,mode in (('reader',resolver_uid,0o700),('donor',0,0o750)):
                path=self.directory/name;path.mkdir(mode=mode);os.chown(path,uid,resolver_gid);path.chmod(mode)
                self.identities[name]=identity(path)
            self.donor=ReplyEndpoint(self.directory/'donor',expected_gid=resolver_gid,group_sender=True)
            if same_pid_reload:
                path=self.directory/'retirement';path.mkdir(mode=0o750);os.chown(path,0,resolver_gid);path.chmod(0o750)
                self.identities['retirement']=identity(path)
                self.retirement=ReplyEndpoint(path,expected_gid=resolver_gid,group_sender=True)
            components=dict(COMPONENTS)
            if refresh:components['refresh']='confirmationrefresh.py'
            component_specs=[SourceSpec('confirmation_'+name+'_source',str(self.root/'dnsalias'/file),0,0,(0o600,),65536) for name,file in components.items()]
            # Like ACK/endpoint source in TrialFeed, these exact embedded bytes
            # are subsequently bound and watched through companion.py itself.
            with SourceAudit(component_specs,ancestor_uids=(0,)) as audit:
                self.sources={name:(self.root/'dnsalias'/file).read_text() for name,file in components.items()};audit.audit()
            for asset in (self.asset,self.key_asset):
                if asset is not None:
                    for spec in asset.source_specs:
                        if spec not in self.source_specs:self.source_specs.append(spec)
            self.token=os.urandom(32)
            self.lock_path=Path(lock_path)
            if not self.lock_path.is_absolute() or '..' in self.lock_path.parts:raise ValueError('canonical native filter lock required')
            self.lock_fd=os.open(self.lock_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            info=os.fstat(self.lock_fd);self.lock_identity=(info.st_dev,info.st_ino)
            self._lock_qualified();self.state='prepared';return self
        except BaseException:
            self.close();raise  # Preserve partial paths for inspected retirement.

    def _owner(self):
        if self.creator!=os.getpid() or self.closed:raise ValueError('live same-process confirmation owner required')

    def _lock_qualified(self):
        _file(self.lock_fd,self.lock_identity)
        i=self.lock_path.lstat()
        if (i.st_dev,i.st_ino)!=self.lock_identity:raise ValueError('named filter lock changed')

    def cleanup_descriptor(self):
        self._owner()
        # The privileged cleanup child loads the same verified package code as
        # this helper. The resolver copy has an unprivileged chroot ancestor.
        return {'native':dict(self.asset.helper_contract),
                'page':self.page.descriptor(),'resolver_uid':self.uid}

    def acknowledge_cleanup(self,pid):
        """Call only after the existing child protocol acknowledges this page."""
        self._owner()
        if self.cleanup_ready or type(pid) is not int or not 0<pid<2**31 or pid==self.creator:raise ValueError('one explicit cleanup child required')
        self.cleanup_watch=ProcessLifetimeWatch(pid)
        self.cleanup_pid=pid;self.cleanup_ready=True

    def available(self):
        # No source or PF qualification is inferred from this flag. The normal
        # per-reply writer/guard still qualifies and synchronizes before publish.
        return (not self.closed and self.cleanup_ready and self.state=='enrolled'
                and self.pending_reload is None and self.cleanup_watch.alive())

    def options(self,settings):
        self._owner()
        if self.state!='prepared' or settings['chroot']!=self.settings['chroot'] or settings['directory']!=self.settings['directory']:
            raise ValueError('exact prepared resolver settings required')
        def inside(path):return str(Path('/')/path.relative_to(settings['chroot'])) if settings['chroot'] else str(path)
        value={'native_confirmation_contract':self.asset.resolver_contract,'confirmation_page':self.page.descriptor(chroot=settings['chroot']),
            'confirmation_sources':dict(self.sources),'native_loader_source':self.asset.loader_source,
            'confirmation_notice':{'directory':inside(self.directory/'reader'),'donor':inside(self.donor.path),
                'token':self.token.hex(),'identity':self.lock_identity,'timeout':1,'source_watches':1}}
        if self.key_asset is not None:value['native_key_contract']=self.key_asset.resolver_contract
        if self.refresh_enabled:value['confirmation_refresh']=True
        if self.retirement is not None:
            value['confirmation_retirement']={'path':inside(self.retirement.path),'token':self.token.hex()}
        return value

    def before_reload(self,*,producer_pid,profile_id,sources,expected_generation=None):
        self._owner()
        if (self.state!='prepared' or not self.cleanup_ready or self.thread is not None
            or type(producer_pid) is not int or not 0<producer_pid<2**31
            or type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}',profile_id)):
            raise ValueError('prepared page, cleanup receipt and exact producer required')
        if type(sources) is not SourceAudit:raise ValueError('pinned source audit required')
        if expected_generation is not None and (type(expected_generation) is not str or not re.fullmatch('[a-f0-9]{32}',expected_generation)):
            raise ValueError('exact announced reader generation required')
        self.producer_pid=producer_pid;self.state='enrolling'
        def enroll():
            try:
                with ProcessLifetimeWatch(producer_pid) as watch:
                    endpoint=self.directory/'reader/replies.sock';deadline=time.monotonic()+8
                    while not endpoint.exists():
                        if self.cancel.wait(.002) or not watch.alive() or time.monotonic()>=deadline:raise TimeoutError('reader did not enroll')
                    if identity(self.directory/'reader')!=self.identities['reader'] or not self.donor.healthy():raise ValueError('notice directory changed')
                    self._lock_qualified()
                    sources.audit()
                    entries=[(self.lock_fd,'file',CapabilityChangeBarrier.metadata(self.lock_fd,'file'))]
                    entries.extend((fd,'file',wanted) for spec,parent,name,fd,wanted in sources.files)
                    entries.extend((fd,'directory',wanted) for parent,name,fd,wanted in sources.directories.values())
                    self.manifest_digest=send_source_watch(self.donor.socket,str(endpoint),entries,
                        token=self.token,restrict=self.asset.module.watch_restrict)
                    self.watch_counts={'files':len(sources.files),'directories':len(sources.directories),'filter_lock':1}
                    if not select.select([self.donor.socket],[],[],1)[0]:raise TimeoutError('reader enrollment receipt absent')
                    receipt,creds=receive(self.donor.socket,expected_uid=self.uid,expected_pid=producer_pid)
                    if (set(receipt)!={'watch_enrolled','profile_id','resolver_generation','source_manifest'}
                        or receipt['source_manifest']!=self.manifest_digest or receipt['watch_enrolled']!=self.token.hex()
                        or receipt['profile_id']!=profile_id or type(receipt['resolver_generation']) is not str
                        or not re.fullmatch('[a-f0-9]{32}',receipt['resolver_generation'])
                        or receipt['resolver_generation']==self.retired_generation
                        or (expected_generation is not None and receipt['resolver_generation']!=expected_generation)):raise ValueError('reader enrollment receipt differs')
                    # A separate watch avoids sharing a consumed kqueue with
                    # the main reload thread. Sources use their pinned audit.
                    sources.audit();self.page.audit();self._lock_qualified()
                    if not watch.alive() or self.cancel.is_set() or not self.cleanup_ready:raise ValueError('enrollment lifetime ended')
                    result=send_observation(self.donor.socket,str(endpoint),{'watch_committed':self.token.hex(),
                        'profile_id':profile_id,'resolver_generation':receipt['resolver_generation'],'source_manifest':self.manifest_digest})
                    if result!='queued':raise ValueError('reader commit not sent; never retry')
                    self.enrolled_generation=receipt['resolver_generation'];self.state='enrolled';self.reason=None
                    if self.refresh_enabled:
                        from .confirmationrefreshowner import RefreshDonor
                        self.refresh_donor=RefreshDonor(self,sources,producer_pid=producer_pid,profile_id=profile_id)
            except Exception as exc:
                self.reason=type(exc).__name__;self.state='disabled';self.authority.invalidate()
        self.thread=threading.Thread(target=enroll,name='dnsalias-confirmation-startup',daemon=True);self.thread.start()

    def poll_reload(self,watch,enrollment):
        """Authenticate lifecycle notices, never infer retirement from a path.

        One old-reader close and one fresh-reader hello are required. Both
        come from the still-watched enrolled process; no notice supplies a path
        or new policy/source identity. Foreign/stale notices cannot revoke it.
        """
        self._owner()
        if self.retirement is None:return None
        if (type(watch) is not ProcessLifetimeWatch or watch.pid!=self.producer_pid
            or watch.lifetime_id!=enrollment.producer.process_start_id or not watch.alive()
            or self.state!='enrolled' or enrollment.generation!=self.enrolled_generation):return None
        if not self.retirement.healthy():raise ValueError('owned retirement endpoint changed')
        fields={'kind','token','profile_id','resolver_generation','generation_started_monotonic','observed_monotonic'}
        for _ in range(8):
            try:value,_=receive(self.retirement.socket,expected_uid=self.uid,expected_pid=self.producer_pid)
            except BlockingIOError:break
            except RejectedMessage:self.notice_rejected=min(2**63-1,self.notice_rejected+1);continue
            now=time.monotonic()
            valid=(type(value) is dict and set(value)==fields and value['kind'] in ('reader_retired','reader_retired_config_check','reader_hello')
                and value['token']==self.token.hex() and value['profile_id']==enrollment.profile_id
                and type(value['resolver_generation']) is str and re.fullmatch('[a-f0-9]{32}',value['resolver_generation'])
                and all(type(value[k]) in (int,float) and math.isfinite(value[k]) and 0<=value[k]<=now for k in ('generation_started_monotonic','observed_monotonic'))
                and value['generation_started_monotonic']<=value['observed_monotonic'] and now-value['observed_monotonic']<8)
            if not valid:self.notice_rejected=min(2**63-1,self.notice_rejected+1);continue
            if value['kind'] in ('reader_retired','reader_retired_config_check'):
                if (value['resolver_generation'],value['generation_started_monotonic'])!=(enrollment.generation,enrollment.started_monotonic):
                    self.notice_rejected=min(2**63-1,self.notice_rejected+1);continue
                if self.pending_reload is None:
                    self.pending_reload={'retired':dict(value),'hello':None,'watch_lifetime':watch.lifetime_id}
                    self.authority.invalidate()
            elif (value['resolver_generation']!=enrollment.generation
                  and value['generation_started_monotonic']>enrollment.started_monotonic):
                if self.pending_hello is None:self.pending_hello=dict(value)
        proof=self.pending_reload
        if proof is not None and self.pending_hello is not None:
            hello=self.pending_hello
            if proof['retired']['observed_monotonic']<=hello['generation_started_monotonic']:
                proof['hello']=hello
            else:self.notice_rejected=min(2**63-1,self.notice_rejected+1);self.pending_hello=None
        return proof

    def prepare_reconfiguration(self,proof,watch,enrollment,sources):
        """A retired reader plus a fresh same-PID hello; never revive a reader."""
        self._owner()
        if (proof is not self.pending_reload or proof is None or proof['hello'] is None
            or type(watch) is not ProcessLifetimeWatch or watch.pid!=self.producer_pid
            or watch.lifetime_id!=proof['watch_lifetime'] or not watch.alive()
            or enrollment.generation!=self.enrolled_generation or self.state!='enrolled'
            or self.thread is None or self.thread.is_alive() or type(sources) is not SourceAudit
            or time.monotonic()-proof['retired']['observed_monotonic']>=8):
            raise ValueError('fresh authenticated old/new reader handoff required')
        self.authority.invalidate();sources.audit();self.page.audit();self._lock_qualified()
        if (not self.cleanup_ready or not self.cleanup_watch.alive() or self.authority.state=='closed'
            or identity(self.directory/'reader')!=self.identities['reader'] or not self.donor.healthy()
            or not self.retirement.healthy()):raise ValueError('reader reload ownership changed')
        if self.refresh_donor is not None:self.refresh_donor.close();self.refresh_donor=None
        self.retired_generation=self.enrolled_generation;self.enrolled_generation=None
        self.pending_reload=self.pending_hello=None
        self.thread=None;self.watch_counts=None;self.manifest_digest=None
        self.reconfigurations+=1;self.state='prepared'

    def prepare_replacement(self,old_watch):
        """Retire a confirmed dead reader, never rearm a surviving reader.

        Called only by the existing same-owner resolver handoff. It separately
        verifies source hashes/identities, TLS configuration and the new PID,
        then calls before_reload before its controlled reload. The page stays
        revoked until that new reader commits enrollment and a current reply
        has completed normal PF synchronization. Old leases are untouched.
        """
        self._owner()
        if (type(old_watch) is not ProcessLifetimeWatch or old_watch.pid!=self.producer_pid
            or old_watch.alive() or old_watch.state!='exited'):
            raise ValueError('confirmed enrolled resolver exit required')
        self.authority.invalidate()
        if self.refresh_donor is not None:self.refresh_donor.close();self.refresh_donor=None
        if self.state!='enrolled' or self.thread is None or self.thread.is_alive():
            self.reason='replacement_without_completed_enrollment';self.state='disabled';return False
        if not self.cleanup_ready or not self.cleanup_watch.alive() or self.authority.state=='closed':
            self.reason='replacement_lifetime_ended';self.state='disabled';return False
        if (identity(self.directory/'reader')!=self.identities['reader']
            or list((self.directory/'reader').iterdir()) or not self.donor.healthy()):
            self.reason='replacement_notice_path_changed';self.state='disabled';return False
        self.retired_generation=self.enrolled_generation;self.enrolled_generation=None
        self.pending_reload=self.pending_hello=None
        self.thread=None;self.watch_counts=None;self.manifest_digest=None
        self.replacements+=1;self.state='prepared';return True

    def close(self):
        if self.creator!=os.getpid():raise ValueError('same-process owner required')
        if self.closed:return
        self.cancel.set()
        if self.authority is not None:self.authority.close()
        elif self.page is not None:self.page.close()
        if self.thread is not None:self.thread.join(timeout=1.2)
        if self.thread is not None and self.thread.is_alive():raise RuntimeError('notice donor still running; retain owned resources')
        if self.refresh_donor is not None:self.refresh_donor.close();self.refresh_donor=None
        if self.donor is not None:self.donor.close()
        if self.retirement is not None:self.retirement.close()
        if self.cleanup_watch is not None:self.cleanup_watch.close()
        if self.lock_fd is not None:os.close(self.lock_fd);self.lock_fd=None
        self.closed=True;self.state='closed'

    def retire(self):
        """Only after hook users, source audits and cleanup child have stopped."""
        self.close()
        for name in ('directory','reader','donor',*(('retirement',) if self.retirement is not None else ())):
            if identity(self.directory if name=='directory' else self.directory/name)!=self.identities[name]:raise ValueError('confirmation directory changed')
        if list((self.directory/'reader').iterdir()) or list((self.directory/'donor').iterdir()):raise ValueError('notice paths still present; inspect')
        expected={'reader','donor','confirmation.page','confirmation.so'}|({'confirmationkey.so'} if self.key_asset is not None else set())
        if self.retirement is not None:
            if list((self.directory/'retirement').iterdir()):raise ValueError('retirement endpoint still present')
            expected.add('retirement')
        if set(p.name for p in self.directory.iterdir())!=expected:raise ValueError('unexpected confirmation resource; inspect')
        self.page.retire();self.asset.retire()
        if self.key_asset is not None:self.key_asset.retire()
        (self.directory/'reader').rmdir();(self.directory/'donor').rmdir()
        if self.retirement is not None:(self.directory/'retirement').rmdir()
        self.directory.rmdir()

    def status(self):
        return {'state':self.state,'reason':self.reason,'cleanup_enrolled':self.cleanup_ready,
            'generation':self.enrolled_generation,'thread_alive':bool(self.thread and self.thread.is_alive()),
            'source_watches':self.watch_counts,
            'producer_pid':self.producer_pid,'replacement_enrollments':self.replacements,
            'same_pid_reloads':self.reconfigurations,'reload_notice_rejected':self.notice_rejected,
            'native_helper_answer_key':self.key_asset is not None,
            'refresh':self.refresh_donor.status() if self.refresh_donor is not None else None,
            'production_lifecycle_qualified':False}
