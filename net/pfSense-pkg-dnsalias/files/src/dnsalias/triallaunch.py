"""On-demand launcher for one operator-approved, initially inactive preview.

No boot registration or automatic Start. A private exclusive claim prevents
duplicate launch and blocks package removal until clean completion. Unknown
outcomes retain that claim; another request never retries or adopts it.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

from .blockowner import run as own_trial,runtime_path
from .checkpointfile import CheckpointFile
from .sourceaudit import SourceAudit,SourceSpec
from .trialprofile import read as read_profile,refresh,PROFILE,PolicyCapacityExceeded
from .trialdiagnostics import summary as diagnostics
from .policyrequest import validate as policy_request,bind as bind_policy,compatible_profile

CLAIM='trial-launch.json'
REQUEST='trial-prepare-request'
OBSERVATION_REQUEST='observation-prepare-request'
PENDING_REQUEST='trial-prepare-pending'
RUNTIME='/var/run/dnsalias-trial'
# Registered sessions require exact saved ownership, fresh empty acquisition,
# independent cleanup and bounded explicit activation. No automatic rule/Start.
REGISTERED_WRITER_READY=True


class LastTrial(CheckpointFile):
    NAME='trial-last.json';PENDING='trial-last.pending';LOCK='trial-last.lock'
    ENVELOPE_FORMAT='dnsalias-last-trial-envelope-1'
    PAYLOAD_FORMAT='dnsalias-last-trial-1'


def _resource_limits(*, confirmation_refresh=False):
    # Source audits deliberately pin several overlapping file/directory sets.
    # The observer's64-descriptor allowance is too small for that composition.
    # Only this detached root helper gets the larger, still-bounded allowance.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    # A refresh temporarily holds the active audit, a fresh audit, and the
    # restricted copies being donated. The provider's full source set can
    # exceed 256 descriptors during that bounded overlap.
    descriptors = 384 if confirmation_refresh else 256
    resource.setrlimit(resource.RLIMIT_NOFILE,(descriptors,descriptors))
    resource.setrlimit(resource.RLIMIT_AS,(192*1024**2,192*1024**2))


def _native(root,data):
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root launcher required')
    root,data=Path(root),Path(data)
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('exact installed launcher required')
    import manage
    manage.verify(root,data)
    return root,data


def _claim(root,data,token):
    if type(token) is not str or not re.fullmatch('[a-f0-9]{32}',token):raise ValueError('explicit launch identity required')
    spec=SourceSpec('launch_claim',str(data/CLAIM),0,0,(0o600,),4096)
    with SourceAudit([spec],ancestor_uids=(0,)) as audit:
        raw=(data/CLAIM).read_bytes();audit.audit()
        digest=hashlib.sha256(raw).hexdigest()
        if digest!=audit.hashes['launch_claim']:raise ValueError('launch claim changed')
    value=json.loads(raw)
    fields={'format','token','root','data','profile_sha256','created_utc','directory','preview_seconds','linger_seconds','operation'}
    if (type(value) is not dict or set(value) not in (fields,fields|{'policy'})
        or value['format']!='dnsalias-launch-claim-2' or value['operation'] not in ('block','observe') or value['token']!=token
        or value['root']!=str(root) or value['data']!=str(data)):
        raise ValueError('owned launch claim required')
    if 'policy' in value:
        if value['operation']!='block':raise ValueError('policy cannot change observation scope')
        policy_request(value['policy'])
    runtime_path(value['directory'])
    return value,digest


def prepare(root,data,*,directory=RUNTIME,preview_seconds=60,linger_seconds=15,operation="block",policy=None):
    """Dispatch once; readiness is read later through the existing UI socket."""
    if operation not in ('block','observe'):raise ValueError('explicit preparation operation required')
    root,data=_native(root,data);read_profile(root,data)
    if any((data/name).exists() or (data/name).is_symlink() for name in (REQUEST,OBSERVATION_REQUEST,PENDING_REQUEST)):
        raise ValueError('queued request must be consumed before preparation')
    if (data/CLAIM).exists() or (data/CLAIM).is_symlink():raise ValueError('existing launch requires status or inspection')
    if (data/LastTrial.PENDING).exists() or (data/LastTrial.PENDING).is_symlink():raise ValueError('uncertain last result requires inspection')
    directory=runtime_path(directory)
    if directory.exists() or directory.is_symlink():raise ValueError('existing runtime requires status or inspection')
    if type(preview_seconds) is not int or not 1<=preview_seconds<=120 or type(linger_seconds) is not int or not 0<=linger_seconds<=60:
        raise ValueError('bounded preview and result-display lifetimes required')
    token=secrets.token_hex(16)
    value={'format':'dnsalias-launch-claim-2','operation':operation,'token':token,'root':str(root),'data':str(data),
           'profile_sha256':hashlib.sha256((data/PROFILE).read_bytes()).hexdigest(),'created_utc':time.time(),
           'directory':str(directory),'preview_seconds':preview_seconds,'linger_seconds':linger_seconds}
    if policy is not None:
        if operation!='block':raise ValueError('named policy requires explicit block preparation')
        value['policy']=policy_request(policy)
    raw=json.dumps(value,sort_keys=True).encode()
    fd=os.open(data/CLAIM,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        if os.write(fd,raw)!=len(raw):raise OSError('incomplete launch claim')
        os.fsync(fd)
    finally:os.close(fd)
    parent=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)
    # Any failure from this point leaves the exact claim for inspection. Never
    # infer that a lost launcher response means the process did not start.
    child=subprocess.Popen([sys.executable,'-B','-m','dnsalias.triallaunch','--run-owned',str(data),token],
        cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
        close_fds=True,start_new_session=True)
    return {'format':'dnsalias-launch-response-1','dispatched':True,'token':token,'pid':child.pid,'started':False}


def consume_request(root,data,*,now,operation="block"):
    """One empty, fresh native-UI request; no automatic retry after consumption."""
    if operation not in ('block','observe'):raise ValueError('explicit preparation operation required')
    data=Path(data);path=data/(OBSERVATION_REQUEST if operation=='observe' else REQUEST)
    if (data/PENDING_REQUEST).exists() or (data/PENDING_REQUEST).is_symlink():
        return None
    try:item=path.lstat()
    except FileNotFoundError:return None
    result={'checked_utc':now,'state':'inspection_required','error':None}
    try:
        other=data/(REQUEST if operation=='observe' else OBSERVATION_REQUEST)
        if other.exists() or other.is_symlink():raise ValueError('conflicting preparation requests require inspection')
        parent=data.lstat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid!=0 or stat.S_IMODE(parent.st_mode)!=0o700
            or not stat.S_ISREG(item.st_mode) or item.st_uid!=0 or item.st_nlink!=1
            or not 0<=item.st_size<=4096 or operation=='observe' and item.st_size or stat.S_IMODE(item.st_mode)!=0o600):raise ValueError('request ownership changed')
        fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            opened=os.fstat(fd);current=path.lstat()
            if any((v.st_dev,v.st_ino,v.st_size,v.st_mtime_ns,v.st_ctime_ns)!=(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns) for v in (opened,current)):
                raise ValueError('request changed before consumption')
            raw=os.read(fd,4097)
            if len(raw)!=item.st_size:raise ValueError('request size changed')
            policy=policy_request(json.loads(raw)) if raw else None
            path.unlink()
        finally:os.close(fd)
        if not -2<=now-item.st_mtime<=30:return result|{'state':'expired'}
        dispatch=(prepare(root,data,operation='observe') if operation=='observe' else
                  prepare(root,data,policy=policy) if policy is not None else prepare(root,data))
        return result|{'state':'dispatched','token':dispatch['token'],'pid':dispatch['pid']}
    except Exception as exc:
        return result|{'error':type(exc).__name__}


def _compatible_native_profile(profile,client=None):
    spec=SourceSpec('native_config','/cf/conf/config.xml',0,0,(0o600,),2*1024**2)
    with SourceAudit([spec],ancestor_uids=(0,)) as audit:
        raw=Path(spec.path).read_bytes();audit.audit()
        if hashlib.sha256(raw).hexdigest()!=audit.hashes['native_config']:raise ValueError('native configuration changed during policy admission')
    return compatible_profile(profile,raw,client=client)


def _registered_authority(root,data,table,occupied,config_sha256):
    """Read-only ownership qualification before constructing any policy owner."""
    import manage
    aliases=manage.inspect_alias_directory(root,data)
    owned=(aliases or {}).get('installation')
    owned_names=set(owned['checkpoint']['plan']['definitions']) if owned is not None else set()
    if table.casefold() not in occupied and table not in owned_names:return None
    from .aliascoordinator import SavedAliasAuthority
    from .reloadlock import SharedReloadLock,ExclusiveConfigLock
    authority=SavedAliasAuthority(root=root,data=data,config='/cf/conf/config.xml',table=table)
    reload=SharedReloadLock('/tmp/filter.lock');exclusive=ExclusiveConfigLock('/tmp/config.lock')
    try:
        with reload,exclusive:review=authority.review(reload,exclusive)
    finally:exclusive.close();reload.close()
    if review['configuration_sha256']!=config_sha256:raise ValueError('configuration changed before registered preview')
    if not REGISTERED_WRITER_READY:raise ValueError('registered writer awaits independent cleanup qualification')
    return authority


def run_owned(root,data,token):
    """One detached child owns its claim, preparation and bounded trial."""
    root,data=_native(root,data);_resource_limits();claim,digest=_claim(root,data,token)
    result=None;error=None;refusal_reason=None;owner_invoked=False;registered_authority=None;stage='approved_profile'
    try:
        profile=read_profile(root,data)
        stage='profile_identity'
        if hashlib.sha256((data/PROFILE).read_bytes()).hexdigest()!=claim['profile_sha256']:
            raise ValueError('approved profile changed since dispatch')
        stage='native_compatibility';profile=_compatible_native_profile(profile,claim.get('policy',{}).get('client'))
        stage='runtime_admission'
        request=refresh(profile)
        if 'policy' in claim:
            stage='named_policy_binding'
            if claim['policy']['block_seconds'] is None:
                from .blockowner import CONTINUOUS_FEED_READY
                if not CONTINUOUS_FEED_READY:raise ValueError('continuous registered feed awaits isolated lifecycle qualification')
            request=bind_policy(request,claim['policy'])
            raw=Path('/cf/conf/config.xml').read_bytes()
            if hashlib.sha256(raw).hexdigest()!=request['native_config_sha256']:raise ValueError('native configuration changed before named preview')
            occupied={node.text.casefold() for node in ET.fromstring(raw).findall('./aliases/alias/name') if node.text}
            stage='registered_alias_qualification'
            registered_authority=_registered_authority(root,data,request['rule']['table'],occupied,request['native_config_sha256'])
        request.update(preview_seconds=claim['preview_seconds'],linger_seconds=claim['linger_seconds'])
        stage='preview_ownership'
        if _claim(root,data,token)[1]!=digest:raise ValueError('launch claim changed before preview')
        owner_invoked=True;stage='policy_owner'
        if claim.get('operation','block')=='observe':
            from .feedowner import run as own_observation
            rule=request.pop('rule')
            request['scope']={'token':rule['token'],'table':rule['table'],'anchor':'dnsalias_trial_'+rule['token']}
            result=own_observation(**request,directory=claim['directory'])
        elif registered_authority is not None:result=own_trial(**request,directory=claim['directory'],registered_authority=registered_authority)
        else:result=own_trial(**request,directory=claim['directory'])
    except Exception as exc:
        error=type(exc).__name__
        if not owner_invoked and isinstance(exc,PolicyCapacityExceeded):refusal_reason='policy_capacity'
    summary={'format':LastTrial.PAYLOAD_FORMAT,'token':token,'finished_utc':time.time(),
        'state':result['state'] if result is not None else 'inspection_required',
        'trial':result.get('observation' if claim.get('operation','block')=='observe' else 'trial') if result is not None else None,
        'error':error or (result.get('error') if result is not None else None),'diagnostics':diagnostics(result),
        'refusal_stage':stage if error is not None and not owner_invoked else None,
        'refusal_reason':refusal_reason,
        'inspection_required':result is None or result.get('inspection_required',True),
        'runtime_removed':result is not None and result.get('runtime_removed') is True,
        'table_removed':result is not None and result.get('table_removed') is True,
        'table_released':result is not None and result.get('table_released') is True}
    # Only a positively known read-only refusal can release its own claim.
    # Once an owner was invoked, all existing uncertain-outcome guards remain.
    if not owner_invoked:
        try:
            if (not any(p.exists() or p.is_symlink() for p in (Path(claim['directory']),data/'hook-trial'))
                and _claim(root,data,token)[1]==digest):
                summary.update(state='refused',inspection_required=False,runtime_removed=True,table_removed=True)
        except Exception:pass
    if summary['inspection_required'] and type(summary['trial']) is dict:
        summary['trial']={**summary['trial'],'state':'inspection_required','error':'Session requires local inspection'}
    with LastTrial(data,expected_uid=0) as last:
        old=last.read();last.save(summary,expected_digest=old['file_sha256'] if old else None)
    if (not summary['inspection_required'] and summary['runtime_removed'] and (summary['table_removed'] or summary['table_released'])
        and _claim(root,data,token)[1]==digest):
        (data/CLAIM).unlink()
        fd=os.open(data,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:os.fsync(fd)
        finally:os.close(fd)
    return summary


def main():
    import manage
    root=Path(__file__).resolve().parents[1]
    if sys.argv[1:]==['--prepare']:
        print(json.dumps(prepare(root,manage.DATA)),flush=True)
    elif len(sys.argv)==4 and sys.argv[1]=='--run-owned':
        run_owned(root,Path(sys.argv[2]),sys.argv[3])
    else:raise ValueError('fixed native preparation entrypoint required')


if __name__=='__main__':main()
