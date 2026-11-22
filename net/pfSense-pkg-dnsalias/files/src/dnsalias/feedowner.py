"""Explicit Start/Stop owner for a bounded, unreferenced trusted reply feed.

No traffic rule or persistent alias is created. A caller supplies a qualified
resolver target and pinned native configuration. Idle expiry changes neither
DNS nor PF. Once started, the independent hook worker handles Stop, deadline
and owner loss; any uncertain table/runtime cleanup remains for inspection.
"""
import json
import os
from pathlib import Path
import re
import sys
import time

from .blockcontrol import ControlSocket
from .blocktrial import gate_identity
from .checkpointfile import CheckpointFile
from .feedcontrol import PreparedObservation
from .indexedproofs import IndexedProofLedger
from .leases import Policy
from .ownedruntime import runtime_path,remove_runtime
from .pfapi import NativePFTables
from .pfwriter import LeaseTableWriter
from .sourceaudit import SourceAudit,SourceSpec
from .trialfeed import TrialFeed
from .trialservice import validate_target,run as run_feed
from .trialtable import TrialTable
from .trialdiagnostics import summary as diagnostics


class _Runtime(CheckpointFile):
    NAME='runtime.json';PENDING='runtime.pending';LOCK='runtime.lock'
    ENVELOPE_FORMAT='dnsalias-observation-runtime-envelope-1'
    PAYLOAD_FORMAT='dnsalias-observation-runtime-1'


def run(target,scope,names,*,directory,native_config_sha256,preview_seconds=60,linger_seconds=15,emit=None):
    target=validate_target(target)
    prepared=PreparedObservation(scope,names,duration_seconds=target['duration_seconds'],preview_seconds=preview_seconds)
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root observation owner required')
    if type(native_config_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',native_config_sha256):
        raise ValueError('independently inspected native configuration hash required')
    if type(linger_seconds) is not int or not 0<=linger_seconds<=60:raise ValueError('bounded result display lifetime required')
    if emit is not None and not callable(emit):raise ValueError('optional event sink required')
    emit=emit or (lambda value:None)
    path=runtime_path(directory)
    import manage
    root,data=Path(target['root']),Path(target['data'])
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('exact installed observation owner required')
    manage.verify(root,data)
    if manage.inspect_trial_directory(root,data) is not None:raise ValueError('previous hook trial requires inspection')
    audit=SourceAudit([SourceSpec('native_config','/cf/conf/config.xml',0,0,(0o600,),2*1024*1024)],ancestor_uids=(0,))
    if audit.hashes!={'native_config':native_config_sha256}:audit.close();raise ValueError('native configuration changed before preview')
    control=receipt=table=native=writer=None;digest=None;created=False;gate=None;inode=None
    result={'format':'dnsalias-observation-owner-result-1','state':'preparing','error':None,
        'scope':prepared.scope,'names':list(prepared.names),'enforcement_applied':False,'rule_created':False,
        'operation':None,'runtime_removed':False,'table_removed':False,'inspection_required':False,
        'started':False,'native_configuration_unchanged':None}
    def record(phase):
        nonlocal digest
        value={'format':_Runtime.PAYLOAD_FORMAT,'root':str(root),'data':str(data),
            'native_config_sha256':native_config_sha256,'phase':phase,'observation':prepared.snapshot(),'diagnostics':diagnostics(result)}
        digest=receipt.save(value,expected_digest=digest)
    def event(value):
        prepared.event(value);record('running');emit(value)
    try:
        path.mkdir(mode=0o700);created=True
        receipt=_Runtime(path,expected_uid=0);record('prepared')
        gate=path/'gate';fd=os.open(gate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.fchmod(fd,0o600);os.fsync(fd)
        finally:os.close(fd)
        inode=gate_identity(gate);control=ControlSocket(path,prepared)
        emit({'event':'control_ready','path':str(control.path),'preview':prepared.snapshot()})
        while True:
            control.poll()
            if prepared.begin():result['started']=True;record('start_consumed');break
            if prepared.state in ('expired','cancelled'):break
            time.sleep(.02)
        if result['started']:
            table=TrialTable(prepared.scope,directory=path,gate_path=gate,gate_inode=inode,
                reload_lock_path='/tmp/filter.lock',config_lock_path='/tmp/config.lock')
            table.create(before_create=lambda:audit.audit()['sources']=={'native_config':native_config_sha256})
            record('table_created')
            native=NativePFTables('',(prepared.scope['table'],),writable=True)
            native.enroll({prepared.scope['table']:set()})
            writer=LeaseTableWriter(IndexedProofLedger([Policy(prepared.scope['table'][3:],prepared.names)]),
                native,reload_lock_path='/tmp/filter.lock')
            operation=run_feed(target,feed=TrialFeed(writer),emit=event,cancel_requested=control.cancellation)
            result['operation']=operation;prepared.finish(operation);record('feed_finished')
            if prepared.state not in ('complete','cancelled'):
                raise RuntimeError('feed restoration or cleanup requires inspection')
            # No table consumer was installed. Close this process's writer
            # before the table owner independently rechecks emptiness/references.
            writer.close();writer=None;native.close();native=None
            result['table_removal']=table.remove(writers_stopped=True,consumer_removed=True)
            result['table_removed']=True
            rollback=operation['rollback']
            result['journal_retirement']=manage.retire_completed_trial(rollback['journal_file_sha256'],
                worker_stopped=rollback.get('worker_exited') is True and rollback.get('worker_exit_code')==0,
                root=root,data=data)
        else:result['table_removed']=True
        result['state']=prepared.state;record('complete')
        emit({'event':'owner_finished','observation':prepared.snapshot(),'table_removed':result['table_removed']})
        until=time.monotonic()+linger_seconds
        while time.monotonic()<until:control.poll();time.sleep(.02)
        result['observation']=prepared.snapshot()
    except Exception as exc:
        result['state']='inspection_required';result['error']=type(exc).__name__;result['inspection_required']=True
        result['table_status']=None if table is None else table.status()
    finally:
        result['observation']=prepared.snapshot()
        # Closing descriptors never retries a PF/DNS mutation or adopts debris.
        for owned in (control,writer,native,table):
            if owned is not None:
                try:owned.close()
                except Exception:result['inspection_required']=True;result['resource_close_error']=True
        if created and not result['inspection_required']:
            try:
                remove_runtime(receipt,digest,gate,inode,table)
                receipt=None;result['runtime_removed']=True
            except Exception:result['inspection_required']=True;result['cleanup_error']=True
        if receipt is not None:receipt.close()
        try:audit.audit();result['native_configuration_unchanged']=True
        except Exception:result['native_configuration_unchanged']=False;result['inspection_required']=True
        audit.close()
        if result['inspection_required']:result['state']='inspection_required'
    return result


if __name__=='__main__':
    raw=sys.stdin.buffer.readline(32769)
    if len(raw)>32768 or not raw.endswith(b'\n'):raise ValueError('bounded explicit owner request required')
    request=json.loads(raw)
    expected={'target','scope','names','directory','native_config_sha256','preview_seconds','linger_seconds'}
    if type(request) is not dict or set(request)!=expected:raise ValueError('complete observation owner request required')
    result=run(**request,emit=lambda value:print(json.dumps({'event':value}),flush=True))
    print(json.dumps({'result':result}),flush=True)
