"""Inactive single-use deletion of a permanently fenced registered IP set.

No process launch, hook/rule/config/table removal, state kill, add operation or
automatic retry. Caller owns independent supervision and the exact private
session directory. A successful exclusive disarm must precede this function.
Observed membership may be enrolled ONLY for deletion, never authorization.
Privileged writers bypassing the qualified locks/protocol are out of scope.
"""
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import time

from .aliascoordinator import SavedAliasAuthority
from .checkpoint import identity
from .checkpointfile import CheckpointFile
from .membershipgate import ExclusiveMembershipGate,validate as validate_gate
from .pfapi import NativePFTables,MAX_BATCH
from .reloadlock import SharedReloadLock,ExclusiveConfigLock,ReloadBusy
from .replygate import clock
from .trialtable import _Receipt as TableReceipt,validate_scope

FORMAT='dnsalias-membership-drain-1'
REASONS={'undo','deadline','writer_lost','parent_lost','heartbeat_expired','rule_absent','private_qualification'}
IMMUTABLE={'format','table','installation_sha256','table_receipt_sha256','boot_id','gate','reason',
           'started_monotonic','started_utc','baseline_members','baseline_sha256'}


def validate(value):
    fields=IMMUTABLE|{'updated_monotonic','phase','confirmed_deleted','mutation_attempted','empty_verified'}
    if type(value) is not dict or set(value)!=fields or value['format']!=FORMAT:
        raise ValueError('complete registered drain receipt required')
    if type(value['table']) is not str or not re.fullmatch('da_[a-z][a-z0-9_]{0,22}',value['table']):
        raise ValueError('exact registered table required')
    for key in ('installation_sha256','table_receipt_sha256','boot_id','baseline_sha256'):identity(value[key])
    validate_gate(value['gate'])
    if type(value['reason']) is not str or value['reason'] not in REASONS:raise ValueError('bounded drain reason required')
    for key in ('started_monotonic','started_utc','updated_monotonic'):clock(value[key])
    if value['updated_monotonic']<value['started_monotonic']:raise ValueError('drain clock regressed')
    count,deleted=value['baseline_members'],value['confirmed_deleted']
    if (type(count) is not int or not 0<=count<=4096 or type(deleted) is not int or not 0<=deleted<=count
        or type(value['mutation_attempted']) is not bool or type(value['empty_verified']) is not bool):
        raise ValueError('bounded explicit drain counts and outcome required')
    phase=value['phase']
    if phase=='prepared':
        if deleted or value['mutation_attempted'] or value['empty_verified']:raise ValueError('prepared drain cannot claim execution')
    elif phase=='intent':
        if not count or not value['mutation_attempted'] or value['empty_verified'] or deleted:
            raise ValueError('single full-set deletion intent required')
    elif phase=='complete':
        if deleted!=count or not value['empty_verified'] or value['mutation_attempted']!=(count>0):
            raise ValueError('completed drain requires empty readback')
    else:raise ValueError('unknown drain phase')
    return json.loads(json.dumps(value,separators=(',',':'),allow_nan=False))


class DrainFile(CheckpointFile):
    NAME='membership-drain.json';PENDING='membership-drain.pending';LOCK='membership-drain.lock'
    ENVELOPE_FORMAT='dnsalias-owned-membership-drain-1';PAYLOAD_FORMAT=FORMAT

    def read(self):
        value=super().read()
        if value is not None:validate(value['checkpoint'])
        return value

    def save(self,value,*,expected_digest):
        value=validate(value);old=self.read()
        if old is None:
            if value['phase']!='prepared':raise ValueError('new drain must begin prepared')
        else:
            previous=old['checkpoint']
            if any(previous[k]!=value[k] for k in IMMUTABLE):raise ValueError('drain identity cannot change')
            allowed={'prepared':{'intent','complete'},'intent':{'complete'},'complete':set()}
            if value['phase'] not in allowed[previous['phase']]:raise ValueError('drain cannot restart or repeat an intent')
            if value['updated_monotonic']<previous['updated_monotonic']:raise ValueError('drain clock regressed')
        return super().save(value,expected_digest=expected_digest)


class DrainFailure(ValueError):
    def __init__(self,stage,mutation_attempted,empty_verified):
        super().__init__('registered drain incomplete during '+stage+'; inspect actual membership and receipt before another action')
        self.stage=stage;self.mutation_attempted=mutation_attempted;self.empty_verified=empty_verified


@contextmanager
def native_guards(reload,exclusive,*,deadline):
    """Bounded waiting for known-unexecuted lock acquisition only.

    Release a partially acquired pair before waiting. Never retries source
    review, a receipt publication, a native mutation or an uncertain operation.
    Reserve time inside the caller's original budget for the actual drain.
    """
    while True:
        try:
            reload.__enter__();exclusive.__enter__();break
        except ReloadBusy:
            exclusive.__exit__();reload.__exit__()
            if time.monotonic()+.1>=deadline:raise
            time.sleep(.02)
        except Exception:
            exclusive.__exit__();reload.__exit__();raise
    try:yield
    finally:exclusive.__exit__();reload.__exit__()


def run_once(authority,fence,*,directory,reload_lock_path,config_lock_path,reason,budget_seconds=2):
    """Clear one exact owned table under a continuously held permanent fence.

    Refuse any previous/pending drain receipt. Fresh locked native definition
    review and two equal membership reads precede a durable full-set intent.
    Any failure preserves that intent; no mutation or journal save is retried.
    Resources supplied by the caller remain borrowed and held on return.
    """
    if type(budget_seconds) not in (int,float) or not .05<=budget_seconds<=2:raise ValueError('bounded drain budget required')
    started=clock(time.monotonic());deadline=started+budget_seconds;stage='validation'
    attempted=False;empty=False;native=store=reload=exclusive=table_receipt=None;binding=None
    def within():
        if time.monotonic()>=deadline:raise ValueError('registered drain deadline')
    def guarded():
        within()
        if not fence.disarmed or not fence.valid():raise ValueError('permanent exclusive membership fence ended')
        if reload is not None and (not reload.valid() or not exclusive.valid() or reload.identity==exclusive.identity):
            raise ValueError('continuous native filter/config guards ended')
        if binding is not None and table_receipt.read()!=binding:raise ValueError('acquired table binding changed')
    try:
        if (type(authority) is not SavedAliasAuthority or type(fence) is not ExclusiveMembershipGate
            or Path(directory)!=fence.path.parent or authority.uid!=os.geteuid()
            or (fence.descriptor['uid'],fence.descriptor['gid'])!=(authority.uid,authority.gid)
            or type(reason) is not str or reason not in REASONS):
            raise ValueError('exact owned authority, exclusive session fence and reason required')
        guarded();stage='table_gate_binding';table_receipt=TableReceipt(directory,expected_uid=authority.uid);binding=table_receipt.read()
        if binding is None:raise ValueError('acquired table receipt required')
        owner=binding['checkpoint'];scope=validate_scope(owner.get('rule'))
        if (owner.get('phase')!='acquired' or scope['table']!=authority.table
            or owner.get('registration_receipt_sha256')!=authority.digest
            or owner.get('registration_boot_id')!=authority.boot
            or owner.get('membership_gate')!=dict(fence.descriptor)):
            raise ValueError('exclusive gate does not fence this exact registered table')
        stage='existing_drain';store=DrainFile(directory,expected_uid=authority.uid)
        if store.read() is not None or (Path(directory)/store.PENDING).exists() or (Path(directory)/store.PENDING).is_symlink():
            raise ValueError('existing drain requires outcome inspection; no retry')
        reload=SharedReloadLock(reload_lock_path,expected_uid=authority.uid)
        exclusive=ExclusiveConfigLock(config_lock_path,expected_uid=authority.uid)
        stage='native_guard_wait'
        with native_guards(reload,exclusive,deadline=deadline):
            stage='native_definition_review';guarded();review=authority.review_cleanup(reload,exclusive,fence);guarded()
            if review['table']!=authority.table or review['boot_id']!=authority.boot:
                raise ValueError('registered authority changed')
            stage='membership_capture';native=NativePFTables('',(authority.table,),writable=True,max_members=4096)
            baseline=native.snapshot();guarded();native.enroll(baseline);guarded()
            addresses=sorted(baseline[authority.table]);count=len(addresses)
            value={'format':FORMAT,'table':authority.table,'installation_sha256':authority.digest,
                'table_receipt_sha256':binding['file_sha256'],
                'boot_id':authority.boot,'gate':dict(fence.descriptor),'reason':reason,
                'started_monotonic':started,'started_utc':clock(time.time()),'updated_monotonic':time.monotonic(),
                'phase':'prepared','baseline_members':count,
                'baseline_sha256':hashlib.sha256('\n'.join(addresses).encode()).hexdigest(),
                'confirmed_deleted':0,'mutation_attempted':False,'empty_verified':False}
            stage='prepared_record';digest=store.save(value,expected_digest=None);guarded()
            operations=0
            if addresses:
                value.update(phase='intent',updated_monotonic=time.monotonic(),mutation_attempted=True)
                stage='intent_record';digest=store.save(value,expected_digest=digest);guarded()
                for offset in range(0,count,MAX_BATCH):
                    stage='membership_delete';guarded();attempted=True
                    native.delete(authority.table,set(addresses[offset:offset+MAX_BATCH]));operations+=1
                    guarded()
            stage='empty_readback';native.audit();guarded()
            if native.total!=0:raise ValueError('registered drain did not empty the table')
            empty=True;value.update(phase='complete',confirmed_deleted=count,empty_verified=True,
                updated_monotonic=time.monotonic())
            stage='completion_record';digest=store.save(value,expected_digest=digest);guarded()
            return {'drained':True,'table':authority.table,'members_removed':count,'kernel_operations':operations,
                'empty_verified':True,'receipt_sha256':digest,'rules_changed':False,'table_removed':False,
                'configuration_changed':False,'states_changed':False,'automatic_retry':False}
    except Exception:
        raise DrainFailure(stage,attempted,empty) from None
    finally:
        for resource in (native,exclusive,reload,store,table_receipt):
            if resource is not None:resource.close()


def finish_owned_session(authority,descriptor,*,directory,reload_lock_path,config_lock_path,writers_stopped):
    """Parent fallback or read-only completion check after both children exit.

    No retry of an existing drain. If the independently created receipt says
    complete, verify its binding and current empty table. If no receipt exists,
    perform the first drain under the permanently exclusive gate. Any pending,
    prepared or uncertain prior action is preserved for explicit inspection.
    """
    if writers_stopped is not True or type(authority) is not SavedAliasAuthority:
        raise ValueError('owned children must be fenced before parent cleanup')
    descriptor=validate_gate(descriptor);directory=Path(directory)
    if directory!=Path(descriptor['path']).parent:raise ValueError('same bound membership directory required')
    disarmed=directory/'membership.disarmed'
    fence=ExclusiveMembershipGate(descriptor,disarmed=disarmed.exists() or disarmed.is_symlink())
    store=owner=reload=config=native=None
    try:
        with fence:
            owner=TableReceipt(directory,expected_uid=authority.uid);binding=owner.read()
            if binding is None:raise ValueError('acquired session binding required')
            receipt=binding['checkpoint']
            if (receipt.get('phase')!='acquired' or receipt.get('membership_gate')!=descriptor
                or receipt.get('registration_receipt_sha256')!=authority.digest
                or receipt.get('registration_boot_id')!=authority.boot
                or receipt.get('rule',{}).get('table')!=authority.table):
                raise ValueError('exact acquired cleanup binding required before disarm')
            if not fence.disarmed:fence.disarm()
            store=DrainFile(directory,expected_uid=authority.uid);record=store.read()
            if (directory/store.PENDING).exists() or (directory/store.PENDING).is_symlink():
                raise ValueError('pending drain requires outcome inspection')
            if record is None:
                return run_once(authority,fence,directory=directory,reload_lock_path=reload_lock_path,
                    config_lock_path=config_lock_path,reason='writer_lost')
            value=record['checkpoint']
            if value['phase']!='complete':raise ValueError('earlier drain requires outcome inspection; no retry')
            if (value['gate']!=descriptor or value['table']!=authority.table
                or value['installation_sha256']!=authority.digest or value['boot_id']!=authority.boot
                or value['table_receipt_sha256']!=binding['file_sha256']
                or receipt.get('phase')!='acquired' or receipt.get('membership_gate')!=descriptor
                or receipt.get('registration_receipt_sha256')!=authority.digest
                or receipt.get('registration_boot_id')!=authority.boot):
                raise ValueError('exact completed registered cleanup required')
            reload=SharedReloadLock(reload_lock_path,expected_uid=authority.uid)
            config=ExclusiveConfigLock(config_lock_path,expected_uid=authority.uid)
            with reload,config:
                authority.review_cleanup(reload,config,fence)
                native=NativePFTables('',(authority.table,),max_members=4096)
                for unused in range(2):
                    if (not fence.valid() or not reload.valid() or not config.valid()
                        or native.snapshot()!={authority.table:set()}):
                        raise ValueError('completed membership cleanup no longer verifies empty')
                if store.read()!=record or owner.read()!=binding:raise ValueError('completed cleanup proof changed')
                return {'empty_verified':True,'previous_drain_verified':True,'receipt_sha256':record['file_sha256'],
                    'kernel_operations':0,'rules_changed':False,'table_removed':False,
                    'configuration_changed':False,'states_changed':False,'automatic_retry':False}
    finally:
        for resource in (native,config,reload,owner,store,fence):
            if resource is not None:resource.close()
