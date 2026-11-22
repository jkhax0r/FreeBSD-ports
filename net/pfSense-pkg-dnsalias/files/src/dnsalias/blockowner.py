"""Single prepared UI trial owner; explicit invocation, no startup registration.

The caller supplies an independently inspected resolver target, exact rule
scope and native configuration hash. Nothing is enforced while waiting for a
Start request. One consumed request rechecks the pinned native configuration
under the table owner's native guards before creating its empty root table.
The qualified supervisor supplies independent rule expiry and DNS rollback.
An idle preview expires or cancels without any PF/DNS mutation.

Errors preserve owned evidence for inspection. This is not an adopter/recovery
daemon: an existing runtime directory is always refused. A successfully owned
trial retires its exact completed journal after worker exit and table removal.
Package/data lifetime remains the caller's responsibility.
"""
import json
import os
from pathlib import Path
import re
import sys
import time

from .blockcontrol import PreparedTrial,ControlSocket
from .blockservice import run as run_block
from .blocktrial import gate_identity
from .checkpointfile import CheckpointFile
from .ownedruntime import runtime_path,remove_runtime
from .sourceaudit import SourceAudit,SourceSpec
from .trialservice import validate_target
from .trialtable import TrialTable
from .trialdiagnostics import summary as diagnostics


class _Runtime(CheckpointFile):
    NAME='runtime.json';PENDING='runtime.pending';LOCK='runtime.lock'
    ENVELOPE_FORMAT='dnsalias-short-runtime-envelope-1'
    PAYLOAD_FORMAT='dnsalias-short-runtime-1'


CONTINUOUS_FEED_READY=False


def run(target,rule,names,*,directory,native_config_sha256,preview_seconds=60,linger_seconds=15,emit=None,block_seconds=5,registered_authority=None):
    """Own one explicitly prepared trial, including an unused preview's cleanup."""
    target=validate_target(target);prepared=PreparedTrial(rule,names,preview_seconds=preview_seconds,block_seconds=block_seconds)
    if block_seconds is None and (not CONTINUOUS_FEED_READY or registered_authority is None):
        raise ValueError('continuous registered feed awaits isolated lifecycle qualification')
    if registered_authority is not None:
        from .aliascoordinator import SavedAliasAuthority
        if (type(registered_authority) is not SavedAliasAuthority
            or registered_authority.root!=Path(target['root']) or registered_authority.data!=Path(target['data'])
            or registered_authority.table!=prepared.rule['table'] or 'policy_name' not in prepared.rule):
            raise ValueError('exact registered named policy authority required')
        prepared.registered_alias=True
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root trial owner required')
    if block_seconds is None:
        if target['duration_seconds'] is not None:raise ValueError('continuous policy requires continuous feed')
    elif (block_seconds==5 and target['duration_seconds']>30 or block_seconds!=5
          and not block_seconds+10<=target['duration_seconds']<=block_seconds+30):raise ValueError('feed must bind the explicit block duration')
    if type(native_config_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',native_config_sha256):
        raise ValueError('independently inspected native configuration hash required')
    if type(linger_seconds) is not int or not 0<=linger_seconds<=60:raise ValueError('bounded result display lifetime required')
    if emit is not None and not callable(emit):raise ValueError('optional event sink required')
    emit=emit or (lambda value:None)
    path=runtime_path(directory)
    import manage
    root,data=Path(target['root']),Path(target['data'])
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('exact installed trial owner required')
    manage.verify(root,data)
    if manage.inspect_trial_directory(root,data) is not None:raise ValueError('previous hook trial requires inspection')
    audit=SourceAudit([SourceSpec('native_config','/cf/conf/config.xml',0,0,(0o600,),2*1024*1024)],ancestor_uids=(0,))
    if audit.hashes!={'native_config':native_config_sha256}:audit.close();raise ValueError('native configuration changed before preview')
    control=receipt=table=None;digest=None;created=False;gate=None;inode=None;history_started=False
    result={'format':'dnsalias-prepared-owner-result-1','state':'preparing','error':None,
            'operation':None,'runtime_removed':False,'table_removed':False,'inspection_required':False,
            'started':False,'native_configuration_unchanged':None}
    def record(phase):
        nonlocal digest
        value={'format':_Runtime.PAYLOAD_FORMAT,'root':str(root),'data':str(data),
            'native_config_sha256':native_config_sha256,'phase':phase,'trial':prepared.snapshot(),'diagnostics':diagnostics(result)}
        digest=receipt.save(value,expected_digest=digest)
    def event(value):
        prepared.event(value);record('running');emit(value)
    try:
        path.mkdir(mode=0o700);created=True
        receipt=_Runtime(path,expected_uid=0);record('prepared')
        gate=path/'gate';fd=os.open(gate,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:os.fchmod(fd,0o600);os.fsync(fd)
        finally:os.close(fd)
        inode=gate_identity(gate)
        control=ControlSocket(path,prepared)
        emit({'event':'control_ready','path':str(control.path),'preview':prepared.snapshot()})
        while True:
            control.poll()
            if prepared.begin():
                result['started']=True;record('start_consumed');break
            if prepared.state in ('expired','cancelled'):break
            time.sleep(.02)
        if result['started']:
            arguments=dict(directory=path,gate_path=gate,gate_inode=inode,
                reload_lock_path='/tmp/filter.lock',config_lock_path='/tmp/config.lock')
            if registered_authority is None:table=TrialTable(prepared.rule,**arguments)
            else:
                from .trialtable import RegisteredTable
                table=RegisteredTable(prepared.rule,authority=registered_authority,**arguments)
            table.create(before_create=lambda:audit.audit()['sources']=={'native_config':native_config_sha256})
            if 'policy_name' in prepared.rule:
                try:
                    from .policyhistory import started
                    started(data,prepared.rule,prepared.names,block_seconds);history_started=True;prepared.history_recorded=True
                except Exception as exc:result['policy_history_error']=type(exc).__name__;prepared.history_recorded=False
            descriptor=None
            if registered_authority is not None:
                from .membershipgate import create as create_membership_gate
                descriptor=create_membership_gate(path,uid=0,gid=0);table.bind_membership_gate(descriptor)
            record('table_created')
            operation=run_block(target,prepared.rule,prepared.names,gate_path=str(gate),gate_inode=inode,
                reload_lock_path='/tmp/filter.lock',emit=event,cancel_requested=control.cancellation,block_seconds=block_seconds,
                names_update_requested=prepared.take_names_update if 'policy_name' in prepared.rule else None,
                registered_authority=registered_authority,membership_gate=descriptor)
            result['operation']=operation;prepared.finish(operation);record('supervisor_finished')
            if not (operation['resources_released'] and operation['rule_removed'] and operation['restoration_verified']
                    and operation['state'] in ('complete','cancelled')):
                raise RuntimeError('supervisor restoration or cleanup requires inspection')
            if registered_authority is None:
                result['table_removal']=table.remove(writers_stopped=True,consumer_removed=True)
                result['table_removed']=True
            else:
                result['table_release']=table.release(writers_stopped=True,consumer_removed=True)
                result['table_released']=True;result['table_retained']=True
            rollback=operation['feed_result']['rollback']
            result['journal_retirement']=manage.retire_completed_trial(rollback['journal_file_sha256'],
                worker_stopped=rollback.get('worker_exited') is True and rollback.get('worker_exit_code')==0,
                root=root,data=data)
        else:
            # No table helper or resolver operation was constructed at all.
            result['table_removed']=True
        result['state']=prepared.state;record('complete')
        emit({'event':'owner_finished','trial':prepared.snapshot(),'table_removed':result['table_removed']})
        until=time.monotonic()+linger_seconds
        while time.monotonic()<until:control.poll();time.sleep(.02)
        result['trial']=prepared.snapshot()
    except Exception as exc:
        result['state']='inspection_required';result['error']=type(exc).__name__;result['inspection_required']=True
        result['table_status']=None if table is None else table.status()
        # No automatic mutation retry or deletion after an uncertain phase.
    finally:
        if history_started:
            try:
                from .policyhistory import ended
                ended(data,prepared.rule['token'],counters=prepared.rule_counters)
            except Exception as exc:result['policy_history_error']=type(exc).__name__
        result['trial']=prepared.snapshot()
        if control is not None:
            try:control.close()
            except Exception:result['inspection_required']=True;result['control_cleanup_error']=True
        if table is not None:table.close()
        if created and not result['inspection_required']:
            try:
                remove_runtime(receipt,digest,gate,inode,table)
                receipt=None;result['runtime_removed']=True
            except Exception:result['inspection_required']=True;result['cleanup_error']=True
        if receipt is not None:receipt.close()
        try:
            audit.audit();result['native_configuration_unchanged']=True
        except Exception:result['native_configuration_unchanged']=False
        audit.close()
        if result['inspection_required']:result['state']='inspection_required'
    return result


if __name__=='__main__':
    # Explicit local operator input, never HTTP parameters or shell evaluation.
    raw=sys.stdin.buffer.readline(32769)
    if len(raw)>32768 or not raw.endswith(b'\n'):raise ValueError('bounded explicit owner request required')
    request=json.loads(raw)
    expected={'target','rule','names','directory','native_config_sha256','preview_seconds','linger_seconds'}
    if type(request) is not dict or set(request)!=expected:raise ValueError('complete owner request required')
    result=run(**request,emit=lambda value:print(json.dumps({'event':value}),flush=True))
    print(json.dumps({'result':result}),flush=True)
