"""One explicitly approved trial scope; read-only admission before UI preview.

The native page cannot provide a target, client, domain, path or command. A local
operator provisions the inspected profile separately. It survives only while
its native configuration, sources, credentials, versions and settings match.
A resolver restart can change PID; the authenticated control endpoint supplies
the new PID and a fresh lifetime watch. No previous runtime/journal is adopted.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import stat
import subprocess
import sys
import time

from .blockcontrol import PreparedTrial
from .dnscheck import query
from .ipc import strict_pairs,finite_float,invalid_number
from .processwatch import ProcessLifetimeWatch
from .runtimecontrol import RuntimeControl,load_credentials,status_value,SETTINGS
from .sourceaudit import SourceAudit,SourceSpec
from .trialservice import validate_target

PROFILE='trial-profile.json'
MAX_BYTES=32768
POLICY_FILES={'pfb_py_data.txt','pfb_py_hsts.txt','pfb_py_ss.txt'}


class PolicyCapacityExceeded(ValueError):
    """Known read-only refusal; public status uses a fixed code, never paths."""
    def __init__(self):super().__init__('policy exceeds approved measured capacity')


def validate(value):
    fields={'format','target','scope','names','native_config_sha256','credential_id',
            'runtime_settings','baseline_answers','minimum_free_bytes','max_policy_bytes'}
    if type(value) is not dict or set(value)!=fields or value['format']!='dnsalias-approved-trial-1':
        raise ValueError('complete independently approved trial profile required')
    target=validate_target(value['target'])
    if target['duration_seconds']>30:raise ValueError('short approved trial required')
    scope=value['scope']
    if type(scope) is not dict or set(scope)!={'client','interface','port','reachable'} or type(scope['reachable']) is not bool:
        raise ValueError('explicit approved single-client rule scope required')
    token='0'*16
    rule={'token':token,'anchor':('userrules/' if scope['reachable'] else '')+'dnsalias_trial_'+token,
          'table':'da_mvp_'+token[:12],**{k:scope[k] for k in ('client','interface','port')}}
    prepared=PreparedTrial(rule,value['names'])
    for key in ('native_config_sha256','credential_id'):
        if type(value[key]) is not str or not re.fullmatch('[a-f0-9]{64}',value[key]):raise ValueError('exact inspected identity required')
    settings=value['runtime_settings']
    if type(settings) is not dict or set(settings)!=set(SETTINGS) or any(type(v) is not str or len(v)>256 for v in settings.values()):
        raise ValueError('complete inspected runtime settings required')
    answers=value['baseline_answers']
    if type(answers) is not list or len(answers)!=len(target['probes']) or any(type(a) is not dict for a in answers):
        raise ValueError('inspected baseline DNS answers required')
    minimum=value['minimum_free_bytes']
    if type(minimum) is not int or not 128*1024**2<=minimum<=1024**4:raise ValueError('bounded positive free-memory admission floor required')
    limits=value['max_policy_bytes']
    if type(limits) is not dict or set(limits)!=(POLICY_FILES if target['mode']=='pfblockerng' else set()):
        raise ValueError('exact policy data capacity limits required')
    if any(type(n) is not int or not 0<=n<=1024**3 for n in limits.values()):raise ValueError('bounded policy capacity required')
    value=value|{'target':target,'names':list(prepared.names)}
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(raw)>MAX_BYTES:raise ValueError('approved profile exceeds size limit')
    return json.loads(raw)


def read(root,data):
    """Read only a private operator-owned regular file, with no symlink reads."""
    root,data=Path(root),Path(data)
    for directory in (root,data):
        item=directory.lstat()
        if not stat.S_ISDIR(item.st_mode) or item.st_uid!=os.geteuid() or stat.S_IMODE(item.st_mode)!=0o700:
            raise ValueError('owned private installed directories required')
    path=data/PROFILE
    spec=SourceSpec('approved_profile',str(path),os.geteuid(),os.getegid(),(0o600,),MAX_BYTES)
    with SourceAudit([spec],ancestor_uids=tuple(dict.fromkeys((0,os.geteuid())))) as audit:
        raw=path.read_bytes();audit.audit()
        if hashlib.sha256(raw).hexdigest()!=audit.hashes['approved_profile']:raise ValueError('approved profile changed while reading')
    value=validate(json.loads(raw,object_pairs_hook=strict_pairs,parse_float=finite_float,parse_constant=invalid_number))
    if value['target']['root']!=str(root) or value['target']['data']!=str(data):raise ValueError('profile belongs to another installation')
    return value


def _command(argv,maximum=1048576):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=2)
    if result.returncode or len(result.stdout)>maximum or len(result.stderr)>4096:raise ValueError('bounded native admission read failed')
    return result.stdout


def provision(value):
    """Explicit operator provisioning; no overwrite and no preview/process."""
    value=validate(value);refresh(value)
    path=Path(value['target']['data'])/PROFILE
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        os.fchmod(fd,0o600)
        if os.write(fd,raw)!=len(raw):raise OSError('incomplete approved profile')
        os.fsync(fd)
    finally:os.close(fd)
    parent=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(parent)
    finally:os.close(parent)
    return {'profile_created':True,'preview_started':False,'policy_applied':False,'sha256':hashlib.sha256(raw).hexdigest()}


def refresh(value):
    """Return a fresh, still-inactive owner request; never write DNS or PF."""
    value=validate(value);target=value['target']
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0:raise ValueError('native root admission required')
    root,data=Path(target['root']),Path(target['data'])
    import manage
    if root!=Path(__file__).resolve().parents[1]:raise ValueError('exact installed admission helper required')
    manage.verify(root,data)
    if manage.inspect_trial_directory(root,data) is not None:raise ValueError('previous trial requires inspection')
    specs=[SourceSpec(**(v|{'modes':tuple(v['modes'])})) for v in target['sources']]
    specs.append(SourceSpec('native_config','/cf/conf/config.xml',0,0,(0o600,),2*1024**2))
    ancestors=tuple(dict.fromkeys((0,*[spec.uid for spec in specs])))
    expected=target['expected_sources']|{'native_config':value['native_config_sha256']}
    with SourceAudit(specs,ancestor_uids=ancestors) as audit:
        if audit.hashes!=expected:raise ValueError('approved source or native configuration changed')
        actual={'pfsense':Path('/etc/version').read_text().strip(),'python':platform.python_version()}
        if target['mode']=='pfblockerng':actual['pfblockerng']=_command(['/usr/local/sbin/pkg','query','%v','pfSense-pkg-pfBlockerNG'],256).strip()
        if any(target['versions'].get(k)!=v for k,v in actual.items()):raise ValueError('approved installed versions changed')
        memory=_command(['/sbin/sysctl','-n','vm.stats.vm.v_free_count','vm.stats.vm.v_page_size'],128).split()
        if len(memory)!=2 or any(not n.isdigit() for n in memory) or int(memory[0])*int(memory[1])<value['minimum_free_bytes']:
            raise ValueError('free memory below approved admission floor')
        swap=_command(['/usr/sbin/swapinfo','-k'],8192).splitlines()[1:]
        if not swap or any(len(r:=line.split())<4 or not r[2].isdigit() or int(r[2])!=0 for line in swap):
            raise ValueError('trial requires unused swap')
        for name,limit in value['max_policy_bytes'].items():
            item=(Path(target['control_directory'])/name).lstat()
            if not stat.S_ISREG(item.st_mode):raise ValueError('policy data file type changed')
            if item.st_size>limit:raise PolicyCapacityExceeded()
        credentials=load_credentials(target['control_directory'],expected_uid=target['control_uid'],expected_gid=target['control_gid'])
        if credentials['credential_id']!=value['credential_id']:raise ValueError('approved resolver credentials changed')
        control=RuntimeControl(credentials['context'],address='127.0.0.1',port=target['control_port'],server_certificate_sha256=credentials['server_certificate_sha256'])
        pid=status_value(control._read(None,time.monotonic()+.5))['pid']
        with ProcessLifetimeWatch(pid) as watch:
            runtime=control.capture(watch)
            if runtime['settings']!=value['runtime_settings'] or runtime['status']['version']!=target['versions']['unbound']:
                raise ValueError('approved resolver settings changed')
            for unused in range(2):
                answers=[query(p['name'],kind=p['kind'],port=target['dns_port'],timeout_seconds=.2) for p in target['probes']]
                if answers!=value['baseline_answers']:raise ValueError('approved DNS policy baseline changed')
            rules=_command(['/sbin/pfctl','-sr'])
            if value['scope']['reachable'] and rules.splitlines().count('anchor "userrules/*" all')!=1:
                raise ValueError('approved native rule anchor changed')
            if audit.audit()['sources']!=expected or not watch.alive():raise ValueError('admission sources or resolver changed')
    token=secrets.token_hex(8);scope=value['scope']
    rule={'token':token,'anchor':('userrules/' if scope['reachable'] else '')+'dnsalias_trial_'+token,
          'table':'da_mvp_'+token[:12],**{k:scope[k] for k in ('client','interface','port')}}
    return {'target':target|{'resolver_pid':pid},'rule':rule,'names':value['names'],
            'native_config_sha256':value['native_config_sha256'],'preview_seconds':60,'linger_seconds':15}
