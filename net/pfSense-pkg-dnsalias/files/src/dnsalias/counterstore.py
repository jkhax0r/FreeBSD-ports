"""Journaled optional counter RAM layout. No hooks, rules or source recovery.

Activation/removal require a stopped resolver. Native scheduling/UI integration
is intentionally separate. Private paths are derived only beneath a dedicated
root-owned test prefix; they cannot select production paths.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import pwd
import sqlite3
import stat
import subprocess
import sys
import time
import uuid
from .checkpointfile import CheckpointFile
from .lifecycle import _Lock,current,fcntl
from . import countercheckpoint as cp

ROOT=Path('/usr/local/libexec/dnsalias');DATA=Path('/var/db/dnsalias')
PROVIDER={
 '/usr/local/pkg/pfblockerng/pfb_unbound.py':'082edc706d00d81a55fdbba6b9da766fb85f9edf2d5b1e146b209517bcc92909',
 '/usr/local/pkg/pfblockerng/pfblockerng.inc':'159cfca9f10291704b7a5cba4612502b48b62acb11e4e57ab9ccd8d6aaf2f2d1'}

class StoreFile(CheckpointFile):
    NAME='counter-ram.json';PENDING='counter-ram.pending';LOCK='counter-ram.lock'
    ENVELOPE_FORMAT='dnsalias-counter-ram-envelope-1';PAYLOAD_FORMAT='dnsalias-counter-ram-1'

def _directory(path,uid,modes):
    cp._path(path);info=path.lstat()
    if not stat.S_ISDIR(info.st_mode)or info.st_uid!=uid or stat.S_IMODE(info.st_mode)not in modes:
        raise ValueError('Counter directory identity changed')
    # Adding/removing owned child directories changes nlink legitimately.
    return list(cp.identity(info)[:-1])

def _sync(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)

class CounterStore:
    def __init__(self,*,private_base=None,quiet=None):
        if os.geteuid()!=0:raise ValueError('Root counter store controller required')
        self.private=private_base is not None
        if self.private:
            base=cp._path(private_base)
            if base.parent!=Path('/tmp')or not base.name.startswith('dnsalias-counter-store-')or base.resolve(strict=True)!=base:
                raise ValueError('Dedicated private counter store prefix required')
            _directory(base,0,(0o700,0o711))
            if not callable(quiet):raise ValueError('Explicit private quiescence proof required')
            self.quiet=quiet;self.parent=base/'resolver';self.control=base/'control'
        else:
            if not sys.platform.startswith('freebsd')or Path(__file__).resolve()!=ROOT/'dnsalias/counterstore.py'or quiet is not None:
                raise ValueError('Canonical native counter store required')
            life=current(ROOT,DATA)
            if life is None:raise ValueError('Native guarded counter operator required')
            user=pwd.getpwnam('unbound')
            if(user.pw_uid,user.pw_gid)!=(59,59):raise ValueError('Qualified resolver identity required')
            self.parent=Path('/var/unbound');self.control=Path('/var/db/dnsalias-counterram');self.quiet=self._native_quiet
        self.source=self.parent/'pfb_py_resolver.sqlite';self.point=self.parent/'dnsalias-counter-ram'
        self.link_pending=self.source.with_name('.pfb_py_resolver.sqlite.dnsalias-counter.pending')
        self.view=self.control/'disk-view';self.ram=self.point/'counter.sqlite';self.disk=self.view/'counter.sqlite'
        self.paths={name:str(getattr(self,name))for name in('source','point','view','control','link_pending')}
        self.relative='dnsalias-counter-ram/counter.sqlite';self.uid=self.gid=59
        self.state=self.receipt=self.journal=self.lock=None

    def _authority(self,control=False):
        if self.private:return
        life=current(ROOT,DATA)
        if life is None or control and not life.control:raise ValueError('Guarded native counter control required')

    def _native_quiet(self):
        process=subprocess.run(['/bin/pgrep','-x','unbound'],capture_output=True,text=True,timeout=2)
        if process.returncode not in(0,1)or process.stderr:raise ValueError('Native resolver inventory unavailable')
        return process.returncode==1 and not process.stdout.strip()

    def _quiescent(self):
        if self.quiet()is not True:raise ValueError('Stop the resolver before counter storage activation or removal')

    def _provider(self):
        if self.private:return
        for name,digest in PROVIDER.items():
            path=Path(name);info=path.lstat()
            if not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or stat.S_IMODE(info.st_mode)&0o022 or info.st_size>2*1048576 or hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
                raise ValueError('Qualified optional provider source required; no hook recovery or source adoption')

    def _inventory(self):
        p=subprocess.run(['/sbin/mount','-p'],capture_output=True,text=True,check=True,timeout=2)
        rows=[line.split()for line in p.stdout.splitlines()]
        return {str(path):[row for row in rows if len(row)>=4 and row[1]==str(path)]for path in(self.point,self.view)}

    def _read(self):
        _directory(self.control,0,(0o700,))
        if os.path.lexists(self.control/StoreFile.PENDING):raise ValueError('Pending counter ownership publication requires inspection')
        with StoreFile(self.control,expected_uid=0)as journal:value=journal.read()
        if value is None:raise ValueError('Unowned counter directory; no adoption')
        state=value['checkpoint']
        if(state.get('paths')!=self.paths or state.get('private')is not self.private or state.get('uid')!=59 or state.get('gid')!=59
            or not re.fullmatch('[a-f0-9]{32}',state.get('token',''))):raise ValueError('Counter store scope differs')
        return value

    @contextmanager
    def _session(self):
        if self.journal is not None:raise ValueError('Fresh counter operation required')
        value=self._read();lock=_Lock(self.control/'counter-operation.lock',fcntl.LOCK_EX)
        try:
            with StoreFile(self.control,expected_uid=0)as journal:
                again=journal.read()
                if again!=value:raise ValueError('Counter state changed before operation')
                self.receipt=value['file_sha256'];self.state=value['checkpoint'];self.journal=journal;self.lock=lock
                yield
        finally:self.journal=self.lock=None;lock.close()

    def _save(self,phase,**fields):
        if self.journal is None or not self.lock.valid():raise ValueError('Exclusive counter operation required')
        self.state.update(fields,phase=phase,updated_utc=time.time())
        self.receipt=self.journal.save(self.state,expected_digest=self.receipt)

    def _database(self,path):
        cp._file(path,59,59,(0o600,0o644))
        db=cp._connection(path,read_only=True,deadline=time.monotonic()+.25)
        try:return cp.validate_database(db)
        finally:db.close()

    def provision(self):
        self._authority(True)
        self._provider();self._quiescent();_directory(self.parent,59,(0o755,))
        if os.path.lexists(self.control):self._read();return {'provisioned':False}
        if os.path.lexists(self.point):raise ValueError('Counter target namespace is occupied; no adoption')
        if os.path.lexists(self.link_pending):raise ValueError('Pending counter link requires inspection')
        if any(self._inventory().values()):raise ValueError('Counter mount namespace is occupied')
        info=cp._file(self.source,59,59,(0o600,0o644));self._database(self.source)
        if any(os.path.lexists(str(self.source)+suffix)for suffix in('-journal','-wal','-shm')):raise ValueError('Counter sidecars require inspection')
        self.control.mkdir(mode=0o700);os.chmod(self.control,0o700)
        state={'format':StoreFile.PAYLOAD_FORMAT,'paths':self.paths,'private':self.private,'uid':59,'gid':59,'token':uuid.uuid4().hex,
            'phase':'prepared','source_identity':list(cp.identity(info)),'source_mode':stat.S_IMODE(info.st_mode),
            'parent_identity':_directory(self.parent,59,(0o755,)),'updated_utc':time.time()}
        with StoreFile(self.control,expected_uid=0)as journal:journal.save(state,expected_digest=None)
        _sync(self.control.parent);return {'provisioned':True}

    def _base_guard(self):
        if _directory(self.parent,59,(0o755,))!=self.state['parent_identity']:raise ValueError('Counter parent replaced')
        link=self.source.lstat()
        if not stat.S_ISLNK(link.st_mode)or list(cp.identity(link))!=self.state['link_identity']or os.readlink(self.source)!=self.relative:
            raise ValueError('Owned counter link changed; no overwrite')

    def _mounted(self):
        self._base_guard();self._mount_guard()

    def _mount_guard(self):
        inventory=self._inventory()
        for path,kind,origin in((self.view,'nullfs',str(self.point)),(self.point,'tmpfs','tmpfs')):
            rows=inventory[str(path)]
            recorded=self.state['view_mount'if kind=='nullfs'else'ram_mount']
            # Native mount-p omits these requested flags on this platform.
            # Compare its actual recorded mount identity/options, plus the
            # separately recorded mounted-directory identity below. Execution
            # denial is qualified with a harmless native binary in tests.
            if len(rows)!=1 or(rows[0][0],rows[0][2])!=(origin,kind)or rows[0]!=recorded:
                raise ValueError('Owned counter mount changed: '+kind+' '+repr(rows)[:1000])
        if _directory(self.view,59,(0o700,))!=self.state['view_mounted_directory_identity']:raise ValueError('Counter disk view replaced')
        if _directory(self.point,59,(0o700,))!=self.state['ram_directory_identity']:raise ValueError('Counter RAM mount replaced')
        if list(cp.identity(cp._file(self.ram,59,59,(0o600,0o644))))!=self.state['ram_identity']:raise ValueError('Counter RAM file replaced')

    def inspect(self,*,include_database=True):
        self._authority()
        if type(include_database)is not bool:raise ValueError('Explicit counter inspection mode required')
        if not os.path.lexists(self.control):return {'configured':False,'mode':'original_disk'}
        value=self._read();self.state=value['checkpoint'];phase=self.state['phase'];inventory=self._inventory()
        checkpoint=self.state.get('last_checkpoint');captured=checkpoint.get('captured_utc')if checkpoint else None
        age=max(0,time.time()-captured)if type(captured)in(int,float)else None
        result={'configured':True,'phase':phase,'mounts':inventory,'last_checkpoint':checkpoint,
            'checkpoint_age_seconds':age,'checkpoint_overdue':age is not None and age>180,
            'last_checkpoint_error':self.state.get('last_checkpoint_error'),
            'durability':'RAM changes since the last successful checkpoint may be lost; failed checkpoints can extend that interval.'}
        if phase=='off':
            if any(inventory.values())or self.source.is_symlink():raise ValueError('Disabled counter storage changed')
            return result|{'mode':'original_disk'}|({'database':self._database(self.source)}if include_database else{})
        if phase!='active':return result|{'mode':'inspection_required','automatic_retry':False}
        self._base_guard()
        if not any(inventory.values()):
            if _directory(self.point,59,(0o700,))!=self.state['disk_directory_identity']:raise ValueError('Counter fallback directory replaced')
            return result|{'mode':'fallback_disk','ram_reactivation_requires_quiescence':True}|({'database':self._database(self.ram)}if include_database else{})
        self._mounted();return result|{'mode':'ram'}|({'database':self._database(self.ram)}if include_database else{})

    def removable(self):
        self._authority()
        if not os.path.lexists(self.control):return {'removable':True,'configured':False}
        state=self._read()['checkpoint']
        own_link=self.source.is_symlink()and os.readlink(self.source)==self.relative
        if state['phase']!='off'or any(self._inventory().values())or own_link or os.path.lexists(self.point)or os.path.lexists(self.view):
            raise ValueError('Disable the owned counter RAM store before package removal')
        return {'removable':True,'configured':True,'retained_control_evidence':True,'foreign_provider_data_preserved':True}

    def _mount(self,kind):
        target=self.view if kind=='nullfs'else self.point;inventory=self._inventory()
        if inventory[str(target)]:raise ValueError('Counter mount already exists; inspect before retry')
        if kind=='nullfs':
            if _directory(self.point,59,(0o700,))!=self.state['disk_directory_identity']or _directory(self.view,0,(0o700,))!=self.state['view_directory_identity']:
                raise ValueError('Counter directory changed before disk-view mount')
        args=['/sbin/mount_nullfs','-o','noexec,nosuid',str(self.point),str(self.view)]if kind=='nullfs'else[
            '/sbin/mount','-t','tmpfs','-o','size=4m,mode=0700,uid=59,gid=59,noexec,nosuid','tmpfs',str(self.point)]
        self._save('mounting_'+kind,dispatched=args)
        try:p=subprocess.run(args,capture_output=True,text=True,timeout=4)
        except subprocess.TimeoutExpired:raise RuntimeError('Counter mount outcome requires inspection; no retry')from None
        rows=self._inventory()[str(target)]
        origin=str(self.point)if kind=='nullfs'else'tmpfs'
        if p.returncode or len(rows)!=1 or(rows[0][0],rows[0][2])!=(origin,kind):raise RuntimeError('Counter mount did not complete; inspect outcome')
        fields={'view_mount':rows[0],'view_mounted_directory_identity':_directory(self.view,59,(0o700,))}if kind=='nullfs'else{'ram_mount':rows[0],'ram_directory_identity':_directory(self.point,59,(0o700,))}
        if kind=='nullfs'and _directory(self.point,59,(0o700,))!=self.state['disk_directory_identity']:
            raise ValueError('Counter backing directory changed while mounting view')
        self._save(kind+'_mounted',**fields)

    def _copy_data(self,source,target):
        info=cp._file(source,59,59,(0o600,0o644));self._database(source)
        descriptor=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before=os.fstat(descriptor);raw=os.read(descriptor,cp.MAX_BYTES+1);after=os.fstat(descriptor)
            if(cp.identity(before)!=cp.identity(info)or cp.identity(after)!=cp.identity(before)or before.st_size!=len(raw)
                or(before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
                raise ValueError('Counter source changed during seed')
        finally:os.close(descriptor)
        if list(cp.identity(source.lstat()))!=list(cp.identity(info)):raise ValueError('Counter source replaced during seed')
        self._quiescent();fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
        try:
            os.fchown(fd,59,59);os.fchmod(fd,self.state['source_mode']);view=memoryview(raw)
            while view:
                written=os.write(fd,view)
                if written<=0:raise OSError('Short counter RAM seed')
                view=view[written:]
            os.fsync(fd)
        finally:os.close(fd)
        self._database(target)
        return {'captured_utc':time.time(),'published_utc':time.time(),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

    @contextmanager
    def _frozen_source(self):
        # No writes are made through this connection. RESERVED excludes
        # concurrent counter updates while allowing our readonly copy views.
        cp._file(self.source,59,59,(0o600,0o644))
        db=sqlite3.connect('file:'+str(self.source)+'?mode=rw',uri=True,timeout=.25)
        try:
            db.execute('PRAGMA trusted_schema=OFF');db.execute('BEGIN IMMEDIATE')
            self._quiescent();yield
        finally:db.close()

    def activate(self):
        self._authority(True)
        self._provider();self._quiescent()
        if not os.path.lexists(self.control):self.provision()
        observed=self.inspect(include_database=False)
        if observed.get('mode')=='ram':return {'active':True,'unchanged':True}
        if observed.get('mode')=='fallback_disk':self.disable()
        with self._session():
            if self.state['phase']not in('prepared','off'):
                raise ValueError('Incomplete counter activation requires inspection; no automatic retry')
            return self._activate_quiescent()

    def _activate_quiescent(self):
        with self._frozen_source():
            phase=self.state['phase']
            if phase in('prepared','off'):
                if os.path.lexists(self.point)or os.path.lexists(self.view):raise ValueError('Counter storage namespace occupied')
                if os.path.lexists(self.link_pending):raise ValueError('Pending counter link requires inspection')
                self._database(self.source)
                self._save('creating_fallback',source_identity=list(cp.identity(self.source.lstat())),source_mode=stat.S_IMODE(self.source.lstat().st_mode))
                self.point.mkdir(mode=0o700);os.chown(self.point,59,59)
                self.view.mkdir(mode=0o700)
                self._save('copying_fallback',disk_directory_identity=_directory(self.point,59,(0o700,)),view_directory_identity=_directory(self.view,0,(0o700,)))
                copied=self._copy_data(self.source,self.ram);self._save('fallback_ready',source_copy=copied)
            else:raise ValueError('Incomplete counter activation requires inspection; no automatic retry')
            self._quiescent();self._mount('nullfs');self._quiescent();self._mount('tmpfs')
            copied=self._copy_data(self.disk,self.ram)
            self._save('ram_seeded',ram_identity=list(cp.identity(self.ram.lstat())),fallback_identity=list(cp.identity(self.disk.lstat())),last_checkpoint=copied)
            # Keep the original regular filename intact until RAM is seeded.
            # The final switch is one atomic replacement of that proven data
            # inode; no provider ever sees an empty destination during setup.
            os.symlink(self.relative,self.link_pending)
            self._save('publishing_link',pending_link_identity=list(cp.identity(self.link_pending.lstat())))
            if list(cp.identity(cp._file(self.source,59,59,(0o600,0o644))))!=self.state['source_identity']:
                raise ValueError('Counter original file changed before cutover')
            self._quiescent();os.replace(self.link_pending,self.source);_sync(self.parent)
            self._save('active',link_identity=list(cp.identity(self.source.lstat())))
            return {'active':True,'unchanged':False,'ram_limit_bytes':4*1048576,'database':self._database(self.ram),'hooks_changed':False}

    def _snapshot(self):
        self._mounted()
        if list(cp.identity(self.disk.lstat()))!=self.state['fallback_identity']:raise ValueError('Counter fallback checkpoint replaced')
        previous=self.disk.read_bytes();self._save('checkpoint_prepared')
        try:result=cp.snapshot(self.ram,self.disk,uid=59,gid=59,guard=self._mounted)
        except(sqlite3.OperationalError,TimeoutError)as error:
            if(self.disk.read_bytes()==previous and not os.path.lexists(str(self.disk)+'.checkpoint.pending')):
                self._mounted();self._save('active',last_checkpoint_error=type(error).__name__)
            raise
        self._save('active',fallback_identity=list(cp.identity(self.disk.lstat())),last_checkpoint=result,last_checkpoint_error=None)
        return result

    def abort(self):
        """Explicit cancellation of a fully recorded pre-publication setup.

        Unknown mount/file outcomes remain inspection-only. The original
        regular counter file must still be the recorded inode; no database is
        restored over another actor's file and no failed action is retried.
        """
        self._authority(True);self._quiescent()
        with self._session():
            phase=self.state['phase']
            if phase not in('prepared','ram_seeded','publishing_link'):
                raise ValueError('Counter setup phase requires inspection before cancellation')
            if list(cp.identity(cp._file(self.source,59,59,(0o600,0o644))))!=self.state['source_identity']:
                raise ValueError('Counter original file changed before cancellation')
            if _directory(self.parent,59,(0o755,))!=self.state['parent_identity']:raise ValueError('Counter parent replaced')
            if phase=='prepared':
                if any(self._inventory().values())or any(os.path.lexists(p)for p in(self.point,self.view,self.link_pending)):
                    raise ValueError('Prepared counter namespace changed; inspect outcome')
            else:
                self._mount_guard()
                if list(cp.identity(cp._file(self.disk,59,59,(0o600,0o644))))!=self.state['fallback_identity']:
                    raise ValueError('Counter fallback changed before cancellation')
                if set(p.name for p in self.point.iterdir())!={'counter.sqlite'}or set(p.name for p in self.view.iterdir())!={'counter.sqlite'}:
                    raise ValueError('Counter directories contain unexpected files')
                if phase=='publishing_link':
                    link=self.link_pending.lstat()
                    if not stat.S_ISLNK(link.st_mode)or list(cp.identity(link))!=self.state['pending_link_identity']or os.readlink(self.link_pending)!=self.relative:
                        raise ValueError('Pending counter link changed before cancellation')
                elif os.path.lexists(self.link_pending):raise ValueError('Unexpected pending counter link')
                self._save('cancelling_setup');self._quiescent()
                if phase=='publishing_link':self.link_pending.unlink();_sync(self.parent)
                self._unmount(self.point,'tmpfs');self._unmount(self.view,'nullfs')
                if(_directory(self.point,59,(0o700,))!=self.state['disk_directory_identity']
                    or _directory(self.view,0,(0o700,))!=self.state['view_directory_identity']
                    or list(cp.identity(cp._file(self.ram,59,59,(0o600,0o644))))!=[self.state['disk_directory_identity'][0],*self.state['fallback_identity'][1:]]):
                    raise ValueError('Counter fallback changed during cancellation')
                self.ram.unlink();self.point.rmdir();self.view.rmdir();_sync(self.parent)
            self._save('off',restored_identity=list(cp.identity(self.source.lstat())))
            return {'cancelled':True,'original_regular_file_preserved':True,'resolver_started':False}

    def checkpoint(self):
        self._authority()
        with self._session():
            if self.state['phase']!='active':raise ValueError('Counter store requires inspection before checkpoint')
            observed=self.inspect()
            if observed['mode']=='fallback_disk':return {'checkpointed':False,'mode':'fallback_disk','live_data_already_on_disk':True}
            return self._snapshot()|{'checkpointed':True,'mode':'ram'}

    def _unmount(self,path,kind):
        rows=self._inventory()[str(path)]
        origin=str(self.point)if kind=='nullfs'else'tmpfs'
        if len(rows)!=1 or(rows[0][0],rows[0][2])!=(origin,kind):raise ValueError('Counter mount ownership changed before removal')
        previous_phase=self.state['phase'];self._save('unmounting_'+kind)
        p=subprocess.run(['/sbin/umount',str(path)],capture_output=True,text=True,timeout=4)
        after=self._inventory()[str(path)]
        if p.returncode or after:
            # A checked refusal differs from an unknown/partial outcome.
            # Preserve the working store only if every original mount, link
            # and live inode still passes its independent ownership checks.
            # The caller receives failure; nothing is retried automatically.
            if kind=='tmpfs'and previous_phase=='active'and p.returncode and after==rows:
                self._mounted();self._save('active',last_operation_error='unmount_refused')
            raise RuntimeError('Counter unmount not confirmed: '+p.stderr.strip()[:180]+'; inspect before retry')
        self._save(kind+'_unmounted')

    def disable(self):
        self._authority(True)
        # Removing our proven data layout never imports/accepts provider code.
        # A later provider upgrade must not strand the owned RAM mount merely
        # because its executable source pin has changed. Path/mount/schema and
        # quiescence checks still apply before every removal action.
        self._quiescent()
        with self._session():
            if self.state['phase']=='off':return {'disabled':True,'unchanged':True}
            if self.state['phase']!='active':raise ValueError('Incomplete counter operation requires inspection before removal')
            observed=self.inspect()
            if observed['mode']=='ram':
                self._snapshot();self._quiescent();self._unmount(self.point,'tmpfs');self._unmount(self.view,'nullfs')
            elif observed['mode']!='fallback_disk':raise ValueError('Counter mode not qualified for removal')
            self._base_guard();self._quiescent()
            if _directory(self.point,59,(0o700,))!=self.state['disk_directory_identity']or _directory(self.view,0,(0o700,))!=self.state['view_directory_identity']:
                raise ValueError('Counter backing directory changed before removal')
            self._database(self.ram)
            if set(path.name for path in self.point.iterdir())!={'counter.sqlite'}or any(self.view.iterdir()):raise ValueError('Counter directories contain unexpected files')
            self._save('restoring_regular');os.replace(self.ram,self.source);_sync(self.parent)
            self.point.rmdir();self.view.rmdir();self._save('off',restored_identity=list(cp.identity(self.source.lstat())))
            return {'disabled':True,'unchanged':False,'source_regular':not self.source.is_symlink(),'database':self._database(self.source)}
