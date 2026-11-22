"""Inactive durable intention journal for a bounded observation-hook trial.

No hook write, reload, timer process or recovery is performed. Phase labels are
caller-reported evidence, not proof of completion. The controller must exist
independently, qualify its process/boot and native-writer coordination, inspect
uncertain outcomes and prove restoration before declaring completion.
An immutable preparation clock pair fixes the deadline; updates never renew it.
Use an explicitly owned private trial directory, not the installed log data.
"""
from dataclasses import asdict
import json
import re

from .checkpoint import identity,elapsed_checked
from .checkpointfile import CheckpointFile,UntrustedCheckpoint
from .hookfile import _manifest
from .replygate import clock
from .sourceaudit import SourceSpec


FORMAT='dnsalias-hook-trial-1'
TRANSITIONS={'prepared':{'armed','conflict','uncertain'},'armed':{'restoring','conflict','uncertain'},
    'restoring':{'restored','conflict','uncertain'},'restored':{'complete','conflict','uncertain'}}
TERMINAL={'complete','conflict','uncertain'}


def _token(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{32}',value):raise ValueError('explicit trial identity required')
    return value


def _spec(value,name):
    if type(value) is not dict or set(value)!={'name','path','uid','gid','modes','max_bytes'}:
        raise ValueError('explicit inspected source specification required')
    if type(value['modes']) not in (tuple,list) or not 1<=len(value['modes'])<=4:raise ValueError('bounded source modes required')
    result=SourceSpec(**(value|{'modes':tuple(value['modes'])}))
    if result.name!=name or result.max_bytes>1024*1024:raise ValueError('bounded trial hook/config source required')
    return result


def validate(value):
    if type(value) is not dict or set(value)!={'format','plan','status'} or value['format']!=FORMAT:
        raise ValueError('complete trial intention required')
    plan=value['plan'];status=value['status']
    fields={'trial_id','boot_id','prepared_monotonic','prepared_utc','duration_seconds','hook','overlay','config','config_sha256'}
    if type(plan) is not dict or set(plan)!=fields:raise ValueError('complete immutable trial plan required')
    _token(plan['trial_id']);identity(plan['boot_id']);clock(plan['prepared_monotonic']);clock(plan['prepared_utc'])
    if plan['duration_seconds'] is not None and (type(plan['duration_seconds']) is not int or not 1<=plan['duration_seconds']<=86400):
        raise ValueError('explicit feed duration or until-stopped operation required')
    hook=_spec(plan['hook'],'selected_hook');config=_spec(plan['config'],'resolver_config')
    if hook.path==config.path or not hook.path.endswith('.py'):raise ValueError('distinct hook and resolver config required')
    _manifest(plan['overlay']);identity(plan['config_sha256'])
    if type(status) is not dict or set(status)!={'phase','worker','updated_monotonic','updated_utc','reason'}:
        raise ValueError('complete bounded trial status required')
    phase=status['phase']
    if type(phase) is not str or phase not in set(TRANSITIONS)|TERMINAL:raise ValueError('unknown trial phase')
    clock(status['updated_monotonic']);clock(status['updated_utc'])
    if status['updated_monotonic']<plan['prepared_monotonic']:raise ValueError('trial status predates preparation')
    worker=status['worker']
    if worker is not None:
        if (type(worker) is not dict or set(worker)!={'pid','epoch'} or type(worker['pid']) is not int
            or not 0<worker['pid']<2**31):raise ValueError('explicit controller identity required')
        _token(worker['epoch'])
    if phase=='prepared' and worker is not None or phase in ('armed','restoring','restored','complete') and worker is None:
        raise ValueError('trial phase and controller identity disagree')
    reason=status['reason']
    if reason is not None and (type(reason) is not str or not re.fullmatch('[A-Za-z0-9_:.-]{1,120}',reason)):
        raise ValueError('bounded non-private status reason required')
    if phase in ('conflict','uncertain') and reason is None:raise ValueError('conflict or uncertainty requires a reason')
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    if len(raw.encode())>32768:raise ValueError('trial intention exceeds cap')
    return json.loads(raw)


def prepare(*,trial_id,boot_id,now,utc_now,duration_seconds,hook,overlay,config,config_sha256):
    if not isinstance(hook,SourceSpec) or not isinstance(config,SourceSpec):raise ValueError('inspected source specifications required')
    return validate({'format':FORMAT,'plan':{'trial_id':trial_id,'boot_id':boot_id,
        'prepared_monotonic':now,'prepared_utc':utc_now,'duration_seconds':duration_seconds,
        'hook':asdict(hook),'overlay':overlay,'config':asdict(config),'config_sha256':config_sha256},
        'status':{'phase':'prepared','worker':None,'updated_monotonic':now,'updated_utc':utc_now,'reason':None}})


def deadline_status(value,*,boot_id,now,utc_now):
    value=validate(value);identity(boot_id);clock(now);clock(utc_now)
    plan,status=value['plan'],value['status']
    if status['phase'] in TERMINAL:return {'decision':'inspect' if status['phase']!='complete' else 'complete','reason':status['phase'],'reload_authorized':False}
    if plan['boot_id']!=boot_id:return {'decision':'inspect','reason':'boot_changed','reload_authorized':False}
    try:age=elapsed_checked((plan['prepared_monotonic'],plan['prepared_utc']),(now,utc_now),.25)
    except ValueError:return {'decision':'restore_due','reason':'clock_discontinuity','reload_authorized':False}
    left=None if plan['duration_seconds'] is None else max(0,plan['duration_seconds']-age)
    return {'decision':'restore_due' if left==0 else 'waiting','remaining_seconds':left,
        'reason':'deadline' if left==0 else None,'reload_authorized':False}


class HookTrialFile(CheckpointFile):
    NAME='hook-trial.json'
    PENDING='hook-trial.pending'
    LOCK='hook-trial.lock'
    ENVELOPE_FORMAT='dnsalias-owned-hook-trial-1'
    PAYLOAD_FORMAT=FORMAT

    def read(self):
        result=super().read()
        if result is not None:validate(result['checkpoint'])
        return result

    def save(self,value,*,expected_digest):
        value=validate(value);previous=self.read()
        if (previous['file_sha256'] if previous else None)!=expected_digest:
            raise UntrustedCheckpoint('trial journal changed; inspect before retry')
        if previous is None:
            if (value['status']['phase']!='prepared' or value['status']['updated_monotonic']!=value['plan']['prepared_monotonic']
                or value['status']['updated_utc']!=value['plan']['prepared_utc']):
                raise ValueError('new trial must begin with its preparation record')
        else:
            old=previous['checkpoint'];before,after=old['status'],value['status']
            if old['plan']!=value['plan']:raise ValueError('trial plan and deadline are immutable')
            if before['phase'] in TERMINAL:raise ValueError('terminal trial outcome requires inspection; never restart automatically')
            if after['phase']!=before['phase'] and after['phase'] not in TRANSITIONS[before['phase']]:
                raise ValueError('trial phase cannot skip restoration or move backward')
            if before['worker'] is not None and before['worker']!=after['worker']:
                raise ValueError('trial controller identity changed')
            if after['updated_monotonic']<before['updated_monotonic']:raise ValueError('trial status clock reversed')
        # Base writer checks the digest again while holding its nonblocking
        # stable journal lock, including immediately before atomic replacement.
        return super().save(value,expected_digest=expected_digest)
