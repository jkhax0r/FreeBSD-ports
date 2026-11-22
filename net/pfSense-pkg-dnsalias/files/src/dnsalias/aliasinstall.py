"""Inactive owned saved-alias installation receipt and read-only reconciliation.

No config write, reload, cache invalidation, PF operation or recovery action.
The private store uses OS ownership and permissions; hashes detect corruption,
not a malicious privileged writer. Caller-reported phases are not independent
proof. A coordinator must qualify fresh locks/captures, source identity, stopped
writers and actual publication before using the receipt for narrow removal.
"""
from dataclasses import asdict
import json
import re

from .aliasrefs import review_saved_set,_tree_digest
from .checkpoint import identity
from .checkpointfile import CheckpointFile,UntrustedCheckpoint
from .replygate import clock
from .sourceaudit import SourceSpec

FORMAT='dnsalias-alias-install-1'
TRANSITIONS={'prepared':{'published','conflict','uncertain'},
    'published':{'complete','conflict','uncertain'}}
TERMINAL={'complete','conflict','uncertain'}


def validate(value):
    if type(value) is not dict or set(value)!={'format','plan','status'} or value['format']!=FORMAT:
        raise ValueError('complete alias installation receipt required')
    plan,status=value['plan'],value['status']
    fields={'installation_id','boot_id','prepared_monotonic','prepared_utc','config','before_file_sha256',
        'after_file_sha256','before_tree_sha256','after_tree_sha256','seed_name','definitions','definition_sha256',
        'prior_alias_container','prior_alias_list'}
    if type(plan) is not dict or set(plan)!=fields:raise ValueError('complete immutable alias installation plan required')
    if type(plan['installation_id']) is not str or not re.fullmatch('[a-f0-9]{32}',plan['installation_id']):
        raise ValueError('explicit installation identity required')
    for key in ('boot_id','before_file_sha256','after_file_sha256','before_tree_sha256','after_tree_sha256','definition_sha256'):
        identity(plan[key])
    if plan['before_file_sha256']==plan['after_file_sha256'] or plan['before_tree_sha256']==plan['after_tree_sha256']:
        raise ValueError('installation must describe a distinct proposed configuration')
    clock(plan['prepared_monotonic']);clock(plan['prepared_utc'])
    spec=plan['config']
    if type(spec) is not dict or set(spec)!={'name','path','uid','gid','modes','max_bytes'} or type(spec['modes']) not in (list,tuple):
        raise ValueError('explicit inspected native configuration specification required')
    spec=SourceSpec(**(spec|{'modes':tuple(spec['modes'])}))
    if spec.name!='firewall_config' or not spec.path.endswith('/config.xml') or spec.modes!=(0o600,):
        raise ValueError('private native config.xml specification required')
    for key in ('prior_alias_container','prior_alias_list'):
        if type(plan[key]) is not bool:raise ValueError('explicit prior alias container shape required')
    if plan['prior_alias_list'] and not plan['prior_alias_container']:raise ValueError('inconsistent prior alias shape')
    reviewed=review_saved_set(seed_name=plan['seed_name'],definitions=plan['definitions'],configuration={},filter_rules='',nat_rules='')
    if reviewed['definition_sha256']!=plan['definition_sha256']:raise ValueError('alias definition digest mismatch')
    if type(status) is not dict or set(status)!={'phase','updated_monotonic','updated_utc','observed_file_sha256','directory_synced','cache_invalidated','reason'}:
        raise ValueError('complete publication status required')
    phase=status['phase']
    if type(phase) is not str or phase not in set(TRANSITIONS)|TERMINAL:raise ValueError('unknown publication phase')
    clock(status['updated_monotonic']);clock(status['updated_utc'])
    if status['updated_monotonic']<plan['prepared_monotonic']:raise ValueError('publication status predates preparation')
    observed=status['observed_file_sha256']
    if observed is not None:identity(observed)
    if any(type(status[key]) is not bool for key in ('directory_synced','cache_invalidated')):
        raise ValueError('explicit publication completion flags required')
    if phase=='prepared' and (observed is not None or status['directory_synced'] or status['cache_invalidated']):
        raise ValueError('prepared receipt cannot claim publication')
    if phase in ('published','complete') and observed!=plan['after_file_sha256']:
        raise ValueError('publication requires matching target readback digest')
    if phase=='complete' and not (status['directory_synced'] and status['cache_invalidated']):
        raise ValueError('publication completion requires directory sync and cache invalidation')
    reason=status['reason']
    if reason is not None and (type(reason) is not str or not re.fullmatch('[A-Za-z0-9_:.-]{1,120}',reason)):
        raise ValueError('bounded non-private publication reason required')
    if phase in ('conflict','uncertain') and reason is None:raise ValueError('unresolved publication requires a reason')
    if phase not in ('conflict','uncertain') and reason is not None:raise ValueError('successful phase cannot carry failure reason')
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
    if len(raw.encode())>65536:raise ValueError('alias installation receipt exceeds cap')
    return json.loads(raw)


def prepare(*,installation_id,boot_id,now,utc_now,config,install_plan,seed_name,definitions,before_file_sha256,after_file_sha256):
    """Bind one caller-validated install candidate; no ownership is inferred."""
    if not isinstance(config,SourceSpec) or type(install_plan) is not dict or install_plan.get('operation')!='append_unused_saved_aliases':
        raise ValueError('inspected config and unused-alias candidate required')
    candidate=install_plan.get('configuration')
    checked=review_saved_set(seed_name=seed_name,definitions=definitions,configuration=candidate,filter_rules='',nat_rules='')
    if (not checked['reference_review_clear'] or _tree_digest(candidate)!=install_plan.get('after_tree_sha256')
        or checked['definition_sha256']!=install_plan.get('definition_sha256')):
        raise ValueError('installation receipt does not match its unused-alias candidate')
    return validate({'format':FORMAT,'plan':{'installation_id':installation_id,'boot_id':boot_id,
        'prepared_monotonic':now,'prepared_utc':utc_now,'config':asdict(config),
        'before_file_sha256':before_file_sha256,'after_file_sha256':after_file_sha256,
        'before_tree_sha256':install_plan['before_tree_sha256'],'after_tree_sha256':install_plan['after_tree_sha256'],
        'seed_name':seed_name,'definitions':definitions,'definition_sha256':install_plan['definition_sha256'],
        'prior_alias_container':install_plan['prior_alias_container'],'prior_alias_list':install_plan['prior_alias_list']},
        'status':{'phase':'prepared','updated_monotonic':now,'updated_utc':utc_now,'observed_file_sha256':None,
            'directory_synced':False,'cache_invalidated':False,'reason':None}})


def reconcile(value,*,boot_id,current_file_sha256,configuration,filter_rules,nat_rules):
    """Classify fresh caller-supplied evidence without retrying or authorizing.

    A different file hash may represent unrelated edits, not lost ownership.
    Incomplete publication and changed boots always require inspection. Even a
    completed receipt with exact definitions and no references only permits a
    later coordinator to consider a removal plan, never automatic deletion.
    """
    value=validate(value);identity(boot_id);identity(current_file_sha256)
    plan,status=value['plan'],value['status'];phase=status['phase']
    checked=review_saved_set(seed_name=plan['seed_name'],definitions=plan['definitions'],configuration=configuration,
        filter_rules=filter_rules,nat_rules=nat_rules)
    same_boot=boot_id==plan['boot_id'];namespace=checked['namespace_state']
    if current_file_sha256==plan['after_file_sha256']:
        state='installed_visible' if namespace=='exact' and _tree_digest(configuration)==plan['after_tree_sha256'] else 'inconsistent_capture'
    elif current_file_sha256==plan['before_file_sha256']:
        state='original_visible' if namespace=='absent' and _tree_digest(configuration)==plan['before_tree_sha256'] else 'inconsistent_capture'
    elif namespace=='exact':state='installed_with_other_changes' if phase=='complete' else 'unconfirmed_installation'
    else:state='namespace_'+namespace
    return {'state':state,'record_phase':phase,'same_boot':same_boot,
        'reference_review':checked,'requires_inspection':True,'write_authorized':False,'removal_authorized':False,
        'retry_authorized':False,'cache_invalidation_recorded':status['cache_invalidated'],
        'directory_sync_recorded':status['directory_synced'],
        'limits':'Caller must bind the file hash and parsed tree to one fresh locked capture. These observations do not prove a write durable, ownership continuous, runtime references complete, or writers retired. No automatic adoption, repair, removal or retry.'}


class AliasInstallFile(CheckpointFile):
    NAME='alias-install.json'
    PENDING='alias-install.pending'
    LOCK='alias-install.lock'
    ENVELOPE_FORMAT='dnsalias-owned-alias-install-1'
    PAYLOAD_FORMAT=FORMAT

    def _validate(self,value):
        return validate(value)

    def read(self):
        result=super().read()
        if result is not None:self._validate(result['checkpoint'])
        return result

    def save(self,value,*,expected_digest):
        value=self._validate(value);previous=self.read()
        if (previous['file_sha256'] if previous else None)!=expected_digest:
            raise UntrustedCheckpoint('alias installation receipt changed; inspect before retry')
        if previous is None:
            if value['status']['phase']!='prepared' or value['status']['updated_monotonic']!=value['plan']['prepared_monotonic'] or value['status']['updated_utc']!=value['plan']['prepared_utc']:
                raise ValueError('new alias receipt must begin with its preparation record')
        else:
            old=previous['checkpoint'];before,after=old['status'],value['status']
            if old['plan']!=value['plan']:raise ValueError('alias installation identity and proposed change are immutable')
            if before['phase'] in TERMINAL:raise ValueError('terminal alias receipt cannot be restarted or replaced')
            if after['phase']!=before['phase'] and after['phase'] not in TRANSITIONS[before['phase']]:
                raise ValueError('alias publication phases cannot skip or move backward')
            if after['updated_monotonic']<before['updated_monotonic']:raise ValueError('alias receipt clock reversed')
            for key in ('directory_synced','cache_invalidated'):
                if before[key] and not after[key]:raise ValueError('recorded publication completion cannot be erased')
        return super().save(value,expected_digest=expected_digest)
