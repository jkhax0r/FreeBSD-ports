"""Temporary DNS-to-PF feed borrowed by the timed hook trial.

The caller owns fresh PF tables. By default these must remain unreferenced by
reachable traffic rules until the operator is confirmed stopped. An explicit
supervised_block_trial mode permits only a separately owned block-only consumer
with an independent timer, feed-process watch and fenced supervisor cleanup.
The caller must qualify and supervise that consumer before activation; this
adapter does not create a rule or confer ownership. Pass rules are not covered.
No table/rule creation, saved configuration, state kill or automatic restart.
The independent hook worker restores DNS on timeout/operator loss. Abandoned
unreferenced tables/resources require the caller's separate inspected cleanup.
"""
import hashlib
import os
from pathlib import Path
import queue
import stat
import sqlite3
import threading
import time

from .ackhookbuild import companion
from .hookbuild import MAX_OBSERVER_SOURCE_BYTES
from .collector import EventStore
from .pfwriter import LeaseTableWriter
from .processwatch import ProcessLifetimeWatch
from .replytelemetry import summarize
from .replydetails import describe
from .replynormalize import ReplyProfile
from .replywriterservice import ReplyWriterService
from .replyowner import PersistentReplyOwner
from .replywriterpump import GenerationPathReceipt
from .sourceaudit import SourceAudit,SourceSpec


def _table_use(value):
    if type(value) is not str or value not in ('unreferenced','supervised_block_trial','dns_aliases'):
        raise ValueError('explicit qualified table consumer mode required')
    return value


class FeedTelemetry:
    """Bounded best-effort statistics, on a separate SQLite owner thread.

    Only already authenticated writer outcomes enter here, AFTER their ACK.
    No DNS work waits for disk, a database lock or a telemetry queue slot.
    Overload/failure is visible; uncertain transactions are never replayed.
    """
    def __init__(self,path,session,profile_id,*,table_use='unreferenced',excluded_addresses=()):
        self.table_use=_table_use(table_use)
        self.path,self.session,self.profile=path,session,profile_id
        self.detail_profile=ReplyProfile('1.26.1',profile_id,excluded_addresses)
        self.queue=queue.Queue(maxsize=128);self.stop=threading.Event()
        self.counters={'offered':0,'persisted':0,'dropped':0,'busy_batches':0}
        self.losses = {'queue_full': 0, 'worker_unavailable': 0, 'database_busy': 0}
        self.last_database_busy = None
        self.exclusions={'request_deadline':0,'helper_outcome':0,'reply_metadata':0}
        self.error=None
        self.thread=threading.Thread(target=self._run,name='dnsalias-feed-statistics',daemon=True)
        self.thread.start()

    def offer(self,outcomes):
        for item in outcomes:
            self.counters['offered']+=1
            if self.stop.is_set() or self.error is not None:
                self.losses['worker_unavailable'] += 1
                self.counters['dropped'] += 1
                continue
            # Source observations have a 60KB receiver bound. 128 outstanding
            # records therefore remain below 8MB even before compacting.
            try:self.queue.put_nowait(item)
            except queue.Full:
                self.losses['queue_full'] += 1
                self.counters['dropped'] += 1

    def _batch(self,first):
        # This wait belongs only to the statistics thread, after DNS ACKs.
        # Coalesce nearby replies into fewer SQLite transactions without an
        # idle timer, a larger queue, or extending the wait on each arrival.
        items=[first];until=time.monotonic()+.02
        while len(items)<32:
            try:items.append(self.queue.get_nowait())
            except queue.Empty:
                remaining=until-time.monotonic()
                if self.stop.is_set() or remaining<=0:break
                try:items.append(self.queue.get(timeout=remaining))
                except queue.Empty:break
        return items

    def _run(self):
        store=None
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                try:
                    store=EventStore(self.path,self.session,busy_timeout_ms=1000,reply_details=True)
                    # This is the independent storage thread, after DNS ACK
                    # processing. Absorb ordinary short collector transactions
                    # without making the DNS producer wait or growing its queue.
                    if hasattr(store, 'db'):
                        store.db.execute('PRAGMA busy_timeout=650')
                    break
                except sqlite3.OperationalError as exc:
                    if getattr(exc,'sqlite_errorcode',0)&255 not in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED):raise
                    self._record_database_busy('open', started, 0)
                    self.stop.wait(.25)
            if store is None:return
            draining = False
            while not self.stop.is_set() or not self.queue.empty():
                try:first=self.queue.get(timeout=.1)
                except queue.Empty:continue
                items=self._batch(first)
                events=[]
                for item in items:
                    try:
                        reply=item['observation']
                        # helper_error can mean unqualified clock/profile; do
                        # not promote that record into trusted reply telemetry.
                        # reload_busy is emitted only after credentials,
                        # generation, clocks and normalization succeeded. The
                        # DNS answer is evidence; its failed PF update must be
                        # visible without being reported as an applied mapping.
                        deferred=(item['ack']['status']=='helper_error' and item.get('reason')=='reload_busy')
                        if item['ack']['status'] not in ('applied','ignored') and not deferred:
                            reason='request_deadline' if item['ack']['status']=='helper_error' and item.get('reason')=='request_budget_expired' else 'helper_outcome'
                            self.exclusions[reason]+=1
                            continue
                        event=summarize(reply,client=reply['client'],profile_id=self.profile)
                        try:event.update(describe(reply,profile=self.detail_profile))
                        except (KeyError,ValueError,TypeError):
                            event.update(answer_details_version=1,answer_records=[],answer_detail_status='invalid_answer_details')
                        event.update(mapping_status=item['reason'],table_ack=item['ack']['status'],
                            table_ack_transport=item['ack_transport'],
                            enforcement_applied=False if self.table_use=='unreferenced' else None,
                            table_use=self.table_use,firewall_decision_observed=False,
                            mapping_coverage_incomplete=deferred or any(self.losses.values()))
                        events.append(event)
                    except (KeyError,ValueError,TypeError):self.exclusions['reply_metadata']+=1
                if events:
                    # Bound the time spent draining queued batches after service Stop.
                    if not draining and self.stop.is_set():
                        if hasattr(store, 'db'):
                            store.db.execute('PRAGMA busy_timeout=100')
                        draining = True
                    started = time.monotonic()
                    try:self.counters['persisted']+=store.insert(events)
                    except sqlite3.OperationalError as exc:
                        code=getattr(exc,'sqlite_errorcode',0)&255
                        if code not in (sqlite3.SQLITE_BUSY,sqlite3.SQLITE_LOCKED) or store.db.in_transaction:raise
                        # EventStore's transaction context has rolled back.
                        # Drop this batch once, never replay an uncertain write.
                        # Fresh later observations can proceed after contention.
                        self.losses['database_busy'] += len(events)
                        self.counters['dropped'] += len(events)
                        self._record_database_busy('insert', started, len(events))
        except Exception as exc:
            self.error=type(exc).__name__
        finally:
            if store is not None:store.close()

    def _record_database_busy(self, operation, started, dropped):
        self.counters['busy_batches'] += 1
        self.last_database_busy = {
            'operation': operation,
            'utc': time.time(),
            'elapsed_ms': round((time.monotonic() - started) * 1000, 1),
            'dropped': dropped,
        }

    def close(self,wait_seconds=.2):
        self.stop.set()
        self.thread.join(timeout=wait_seconds)
        if self.thread.is_alive():
            return False
        # The feed owner stops collecting before close. Records still in the
        # queue were never attempted, even if opening the database failed.
        # An insert removed from the queue may have an unknown outcome.
        while True:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                break
            self.losses['worker_unavailable'] += 1
            self.counters['dropped'] += 1
        return True

    def status(self):
        losses = dict(self.losses)
        excluded=dict(self.exclusions)
        busy = self.last_database_busy
        return dict(self.counters)|{'dropped':sum(losses.values()),'dropped_by_reason':losses,'invalid':sum(excluded.values()),'excluded_by_reason':excluded,
            'last_database_busy': dict(busy) if busy is not None else None,
            'error':self.error,'queued':self.queue.qsize(),
            'thread_alive':self.thread.is_alive(),'dns_waits_for_storage':False}


class TrialFeed:
    """Single-use adapter with a caller-owned fresh LeaseTableWriter."""
    def __init__(self,writer,*,table_use='unreferenced',supervisor_pid=None,persistent=False,confirmation_owner=None):
        self.table_use=_table_use(table_use)
        if type(persistent) is not bool or (persistent and self.table_use!='dns_aliases'):
            raise ValueError('persistent producer handoff belongs only to DNS aliases')
        if self.table_use=='supervised_block_trial':
            if type(supervisor_pid) is not int or supervisor_pid!=os.getppid():
                raise ValueError('direct live block-trial supervisor required')
        elif supervisor_pid is not None:raise ValueError('supervisor only belongs to explicit block trial')
        if (type(writer) is not LeaseTableWriter or writer.state!='ready'
            or writer.updates or writer.writer.total):raise ValueError('fresh empty borrowed writer required')
        self.writer=writer;self.directory=self.ack=self.source=None
        if confirmation_owner is not None:
            from .confirmationowner import ConfirmationOwner
            if (type(confirmation_owner) is not ConfirmationOwner or not persistent
                or writer.confirmation is not confirmation_owner.authority):raise ValueError('exact persistent confirmation owner required')
        self.confirmation_owner=confirmation_owner
        self.persistent = persistent
        self.owner = PersistentReplyOwner(writer, allow_reported_reply_loss=table_use == 'dns_aliases') if persistent else None
        self.paths=[];self.recorded_route=None;self.retired_path_count=0
        self.socket_count=1
        self.identities={};self.source_audit=None;self.telemetry=None
        self.native_asset=None;self.extract_asset=None;self.generation_asset=None;self.extra_sources=[]
        self.service=None;self.retirement=None;self.cleanup=None
        self.counts={};self.peak_members=0
        self.supervisor=ProcessLifetimeWatch(supervisor_pid) if supervisor_pid is not None else None

    @staticmethod
    def _identity(path):
        value=path.lstat()
        return value.st_dev,value.st_ino,value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode),stat.S_IFMT(value.st_mode)

    def prepare(self,target,trial_id,settings,bodies):
        if self.directory is not None:raise ValueError('feed cannot be reused')
        parent=Path(target['control_directory'])
        self.directory=parent/('daf-'+trial_id)
        self.directory.mkdir(mode=0o750);os.chown(self.directory,0,target['control_gid']);self.directory.chmod(0o750)
        self.identities['directory']=self._identity(self.directory)
        self.ack=self.directory/'ack';self.ack.mkdir(mode=0o700)
        os.chown(self.ack,target['control_uid'],target['control_gid']);self.ack.chmod(0o700)
        self.identities['ack']=self._identity(self.ack)
        package=Path(target['root'])/'dnsalias'
        registry_hashes={}
        if self.table_use=='dns_aliases':
            from .registryentry import enrollment_sources
            registry_specs,registry_hashes=enrollment_sources(target['root'],target['data'])
            self.extra_sources.extend(registry_specs)
        extra=[SourceSpec(name,str(package/file),0,0,(0o600,),65536) for name,file in
            (('ack_source','replyack.py'),('endpoint_source','replyendpoint.py'))]
        with SourceAudit(extra,ancestor_uids=(0,)) as audit:
            ack_source=(package/'replyack.py').read_text();endpoint_source=(package/'replyendpoint.py').read_text()
            audit.audit()
        reply_directory=str(Path('/')/self.ack.relative_to(settings['chroot'])) if settings['chroot'] else str(self.ack)
        from .nativeasset import NativeWireAsset,NativeExtractAsset,NativeGenerationAsset
        from .ipc import configure_native_wire
        self.native_asset=NativeWireAsset.prepare(target['root'],self.directory,settings,resolver_uid=target['control_uid'],expected_directory=self.identities['directory'])
        self.extract_asset=NativeExtractAsset.prepare(target['root'],self.directory,settings,resolver_uid=target['control_uid'],expected_directory=self.identities['directory'])
        if self.persistent:
            self.generation_asset=NativeGenerationAsset.prepare(target['root'],self.directory,settings,resolver_uid=target['control_uid'],expected_directory=self.identities['directory'])
        native={}
        for asset,key in ((self.native_asset,'native_contract'),(self.extract_asset,'native_extract_contract'),(self.generation_asset,'native_generation_contract')):
            if asset is None:continue
            # Optional modules share one independently audited loader.
            for spec in asset.source_specs:
                if spec not in self.extra_sources:self.extra_sources.append(spec)
            if 'native_loader_source' in native and native['native_loader_source']!=asset.loader_source:
                raise ValueError('native loader changed between asset preparations')
            native[key]=asset.resolver_contract;native['native_loader_source']=asset.loader_source
        configure_native_wire(self.native_asset.module if self.native_asset is not None else None)
        if self.confirmation_owner is not None:
            options=self.confirmation_owner.options(settings)
            if 'native_loader_source' in native and native['native_loader_source']!=options['native_loader_source']:
                raise ValueError('confirmation native loader differs')
            native.update(options)
            for spec in self.confirmation_owner.source_specs:
                if spec not in self.extra_sources:self.extra_sources.append(spec)
        if self.persistent:
            from .replyendpoint import MAX_ACK_SOCKETS
            self.socket_count=min(MAX_ACK_SOCKETS,int(settings['num-threads']))
        text,manifest=companion(observer_source=bodies['observer_source'],transport_source=bodies['transport_source'],
            acknowledger_source=ack_source,endpoint_source=endpoint_source,helper_pid=os.getpid(),reply_directory=reply_directory,
            per_generation=self.persistent,socket_count=self.socket_count,**native)
        self.source=self.directory/'companion.py'
        fd=os.open(self.source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchown(fd,0,0);os.fchmod(fd,0o600)
            raw=text.encode()
            with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        except Exception:raise
        self.identities['source']=self._identity(self.source)
        self.digest=hashlib.sha256(raw).hexdigest()
        spec=SourceSpec('observer_source',str(self.source),0,0,(0o600,),MAX_OBSERVER_SOURCE_BYTES)
        self.source_audit=SourceAudit([spec,*self.extra_sources],ancestor_uids=tuple(dict.fromkeys((0,target['control_uid']))))
        if any(self.source_audit.hashes[name]!=digest for name,digest in registry_hashes.items()):
            raise ValueError('Native registry sources changed before feed enrollment')
        if self.source_audit.hashes['observer_source']!=self.digest:raise ValueError('companion publication changed')
        return spec,text,manifest

    def before_reload(self,*,producer_pid,profile_id,sources,expected_generation=None):
        if self.confirmation_owner is not None:
            self.confirmation_owner.before_reload(producer_pid=producer_pid,profile_id=profile_id,sources=sources,expected_generation=expected_generation)

    def start(self,startup,*,auditor,watch,data,session,producer_gid):
        if self.source_audit is None:raise ValueError('prepared feed required')
        if self.service is not None:
            if not self.persistent or not self.service.resources_releasable or self.owner.session is not None:
                raise ValueError('previous receiver must release resources before a persistent handoff')
            self.retire_paths()
        if self.telemetry is not None and self.telemetry.profile!=startup.expected.identifier:
            raise ValueError('persistent telemetry cannot silently change source profile')
        self.service=ReplyWriterService(startup,auditor=auditor,watch=watch,writer=self.writer,
            reply_directory=str(self.ack),producer_gid=producer_gid,table_audit_interval=2,
            lease_owner=self.owner,per_generation=self.persistent,socket_count=self.socket_count)
        if self.telemetry is None:
            self.telemetry=FeedTelemetry(Path(data)/'events.sqlite',session,startup.expected.identifier,table_use=self.table_use,
                                         excluded_addresses=startup.expected.excluded_addresses)
        return self.service

    def retire_paths(self):
        """Off-path transition/Stop cleanup; never a periodic query-path scan."""
        for receipt,watch in tuple(self.paths):
            if receipt.absent():
                receipt.close();self.retired_path_count+=1;self.paths.remove((receipt,watch))
            elif not watch.alive() and watch.state=='exited':
                receipt.remove_after_exit(watch);self.retired_path_count+=1;self.paths.remove((receipt,watch))

    def expire(self):
        """Schedule known deadlines while no DNS producer is qualified."""
        if self.owner is None:raise ValueError('persistent lease owner required')
        expiry=self.owner.next_expiry_attempt();now=time.monotonic()
        if expiry is not None and expiry<=now:self.owner.expire(deadline=now+.04)

    def collect(self):
        if self.supervisor is not None and not self.supervisor.alive():
            raise RuntimeError('block-trial supervisor ended')
        outcomes=self.service.take_outcomes()
        if (self.persistent and self.service.route is not None and self.service.startup.enrollment is not None
            and self.recorded_route is not self.service.route):
            self.retire_paths()
            if len(self.paths)>=2:raise ValueError('unresolved generation paths require inspection')
            receipt=GenerationPathReceipt(self.service.route,self.service.startup.enrollment)
            self.paths.append((receipt,self.service.watch));self.recorded_route=self.service.route
        for item in outcomes:
            key=item['ack']['status'];self.counts[key]=self.counts.get(key,0)+1
        self.peak_members=max(self.peak_members,self.writer.writer.total)
        self.telemetry.offer(outcomes)
        if (self.confirmation_owner is not None and self.confirmation_owner.refresh_donor is not None
            and self.service.state=='running' and self.service.pump.drained):
            self.confirmation_owner.refresh_donor.poll(self.service.session)
        return outcomes

    def finish(self,*,restoration_verified,resources_released):
        # Hook restoration is independent. This path retires only a healthy
        # writer, once, after its receive loop has stopped. Failure is retained.
        error=None
        if self.persistent and resources_released:
            try:self.retire_paths()
            except Exception as exc:error='generation_cleanup:'+type(exc).__name__
        disarmed=self.writer.membership_gate is not None and not self.writer.membership_gate.available()
        if resources_released and self.writer.membership_gate is not None and (self.table_use!='dns_aliases' or disarmed):
            try:self.retirement=self.writer.retire_external(deadline=time.monotonic()+.5)
            except Exception as exc:error=error or type(exc).__name__
        elif resources_released and self.writer.state=='ready':
            try:self.retirement=self.writer.retire(deadline=time.monotonic()+.5)
            except Exception as exc:error=error or type(exc).__name__
        telemetry_closed=True if self.telemetry is None else self.telemetry.close(1.2)
        removed=False
        if restoration_verified and resources_released and self.directory is not None:
            try:
                for name,path in (('directory',self.directory),('ack',self.ack),('source',self.source)):
                    if path is None or self._identity(path)!=self.identities[name]:raise ValueError('feed resource identity changed')
                self.source_audit.audit()
                expected_files={'ack','companion.py'}|{asset.path.name for asset in (self.native_asset,self.extract_asset,self.generation_asset) if asset is not None}
                if set(p.name for p in self.directory.iterdir())!=expected_files or list(self.ack.iterdir()):
                    raise ValueError('feed resources still used or changed')
                if hashlib.sha256(self.source.read_bytes()).hexdigest()!=self.digest:raise ValueError('companion changed')
                self.source_audit.close();self.source_audit=None
                if self.native_asset is not None:self.native_asset.retire()
                if self.extract_asset is not None:self.extract_asset.retire()
                if self.generation_asset is not None:self.generation_asset.retire()
                self.source.unlink();self.ack.rmdir();self.directory.rmdir();removed=True
            except Exception as exc:error=error or type(exc).__name__
        self.cleanup={'owned_resources_removed':removed,'telemetry_closed':telemetry_closed,'error':error}
        if self.source_audit is not None:
            self.source_audit.close();self.source_audit=None
        if resources_released:
            from .ipc import configure_native_wire
            configure_native_wire(None)
        if self.supervisor is not None:self.supervisor.close()
        for receipt,watch in self.paths:receipt.close()
        return self.status()

    def status(self):
        return {'mode':'persistent_dns_alias_feed' if self.table_use=='dns_aliases' else 'unreferenced_table_feed' if self.table_use=='unreferenced' else 'supervised_block_trial_feed',
            'table_use':self.table_use,'traffic_rules_managed':False,
            'persistent_producer_handoff':self.persistent,'retired_generation_paths':self.retired_path_count,
            'confirmation':self.confirmation_owner.status() if self.confirmation_owner is not None else {'state':'not_enabled'},
            'native_codec':self.native_asset.status() if self.native_asset is not None else {'enabled':False},
            'native_extractor':self.extract_asset.status() if self.extract_asset is not None else {'enabled':False},
            'native_generation':self.generation_asset.status() if self.generation_asset is not None else {'enabled':False},
            'pending_generation_paths':len(self.paths),
            'enforcement_applied':False if self.table_use=='unreferenced' else None,'acks':dict(self.counts),
            'peak_members':self.peak_members,'writer':self.writer.status(),'retirement':self.retirement,
            'telemetry':self.telemetry.status() if self.telemetry else None,'cleanup':self.cleanup,
            'supervisor':self.supervisor.status() if self.supervisor else None,
            'crash_cleanup':'Caller must disarm any owned consumer, confirm operator exit and inspect its tables; no automatic adoption'}
