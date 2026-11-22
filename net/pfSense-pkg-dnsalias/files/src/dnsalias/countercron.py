"""Owned native cron.d checkpoint entry; never edits the main crontab/config."""
import hashlib
import os
from pathlib import Path
import stat
from .checkpointfile import CheckpointFile
from . import countercheckpoint as cp
from .counterstore import _directory,_sync

BODY=(b'# DNS Alias owned optional counter RAM checkpoint.\n'
      b'* * * * * root /usr/local/bin/python3.11 -B /usr/local/libexec/dnsalias/dnsalias/lifecycle.py operator counterram checkpoint >/dev/null 2>&1\n')

class CronFile(CheckpointFile):
    NAME='counter-cron.json';PENDING='counter-cron.pending';LOCK='counter-cron.lock'
    ENVELOPE_FORMAT='dnsalias-counter-cron-envelope-1';PAYLOAD_FORMAT='dnsalias-counter-cron-1'

def fingerprint(info):
    return list(cp.identity(info)) + [info.st_size,info.st_mtime_ns,info.st_ctime_ns]

class CounterCron:
    def __init__(self,store):
        self.store=store
        self.path=(store.control.parent/'cron.d/dnsalias_counterram')if store.private else Path('/etc/cron.d/dnsalias_counterram')
        # cron.d must never see an uncommitted staging entry.
        self.pending=self.path.with_name('.'+self.path.name+'.pending')

    def _entry(self):
        info=cp._file(self.path,0,0,(0o600,));fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            if fingerprint(os.fstat(fd))!=fingerprint(info):raise ValueError('Cron entry replaced before read')
            raw=os.read(fd,4097)
            if len(raw)!=info.st_size or fingerprint(os.fstat(fd))!=fingerprint(info)or fingerprint(self.path.lstat())!=fingerprint(info):
                raise ValueError('Cron entry changed while reading')
        finally:os.close(fd)
        return {'fingerprint':fingerprint(info),'sha256':hashlib.sha256(raw).hexdigest()}

    def _owner(self,journal):
        value=journal.read()
        if os.path.lexists(self.store.control/CronFile.PENDING)or os.path.lexists(self.pending):
            raise ValueError('Pending cron operation requires inspection')
        if value is None:
            if os.path.lexists(self.path):raise ValueError('Unowned cron entry; no adoption')
            return None
        state=value['checkpoint']
        if(state.get('entry')!=str(self.path)or state.get('store_token')!=self.store._read()['checkpoint']['token']
            or state.get('phase')not in('installed','removed')):
            raise ValueError('Incomplete or foreign cron ownership; inspect before retry')
        if state['phase']=='installed':
            if self._entry()!=state['source']:raise ValueError('Owned cron entry changed; no overwrite or removal')
        elif os.path.lexists(self.path):raise ValueError('Foreign cron entry appeared after removal')
        return value

    def inspect(self):
        self.store._authority()
        if not os.path.lexists(self.store.control):
            if os.path.lexists(self.path):raise ValueError('Unowned cron entry; no adoption')
            return {'installed':False}
        self.store._read()
        with CronFile(self.store.control,expected_uid=0)as journal:value=self._owner(journal)
        return {'installed':value is not None and value['checkpoint']['phase']=='installed','owner_receipt_present':value is not None,
            'entry':str(self.path),'period_seconds':60}

    def install(self):
        self.store._authority(True)
        with self.store._session():
            if self.store.inspect()['mode']not in('ram','fallback_disk'):raise ValueError('Configured active counter store required before scheduling')
            with CronFile(self.store.control,expected_uid=0)as journal:
                old=self._owner(journal)
                if old is not None and old['checkpoint']['phase']=='installed':
                    if old['checkpoint']['source']['sha256']!=hashlib.sha256(BODY).hexdigest():raise ValueError('Explicit owned cron source upgrade required')
                    return {'installed':True,'unchanged':True}
                if not os.path.lexists(self.path.parent):self.path.parent.mkdir(mode=0o755)
                _directory(self.path.parent,0,(0o700,0o755))
                state={'format':CronFile.PAYLOAD_FORMAT,'entry':str(self.path),'store_token':self.store.state['token'],'phase':'prepared',
                    'source_sha256':hashlib.sha256(BODY).hexdigest()}
                digest=journal.save(state,expected_digest=old['file_sha256']if old else None)
                fd=os.open(self.pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    os.fchmod(fd,0o600);data=memoryview(BODY)
                    while data:
                        n=os.write(fd,data)
                        if n<=0:raise OSError('Short counter cron publication')
                        data=data[n:]
                    os.fsync(fd)
                finally:os.close(fd)
                # New entry publication is exclusive, even if a foreign actor
                # creates the final name during this operation.
                os.link(self.pending,self.path,follow_symlinks=False);self.pending.unlink();_sync(self.path.parent)
                source=self._entry()
                if source['sha256']!=hashlib.sha256(BODY).hexdigest():raise ValueError('Cron entry readback differs; inspect outcome')
                state.update(phase='installed',source=source);journal.save(state,expected_digest=digest)
                return {'installed':True,'unchanged':False,'period_seconds':60,'main_crontab_modified':False}

    def remove(self):
        self.store._authority(True)
        if not os.path.lexists(self.store.control):return self.inspect()|{'removed':False}
        with self.store._session():
            with CronFile(self.store.control,expected_uid=0)as journal:
                old=self._owner(journal)
                if old is None or old['checkpoint']['phase']=='removed':return {'removed':False,'already_absent':True}
                state=old['checkpoint']|{'phase':'removing'};digest=journal.save(state,expected_digest=old['file_sha256'])
                if self._entry()!=state['source']:raise ValueError('Cron entry changed before removal')
                self.path.unlink();_sync(self.path.parent)
                state.update(phase='removed');journal.save(state,expected_digest=digest)
                return {'removed':True,'main_crontab_modified':False}
