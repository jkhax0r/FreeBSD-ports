"""Inactive narrow removal receipt, bound to a completed owned installation.

This only plans removal of exact unused saved aliases. It does not stop writers,
remove PF tables, reload filters or restore an earlier whole configuration.
Independent recovery still needs fresh guarded captures and actual file outcome
inspection. Original installation identity and current operation boot are bound
separately: unused definition removal can follow a reboot, while no lease or
incomplete-install adoption is provided.
"""
import copy

from .aliasinstall import AliasInstallFile,FORMAT as INSTALL_FORMAT,validate as validate_install
from .aliasrefs import review_saved_set,_tree_digest
from .checkpoint import identity
from .sourceaudit import SourceSpec

FORMAT='dnsalias-alias-remove-1'
BOUND_FIELDS=('installation_id','config','seed_name','definitions','definition_sha256',
              'prior_alias_container','prior_alias_list')


def validate(value):
    if type(value) is not dict or value.get('format')!=FORMAT or type(value.get('plan')) is not dict:
        raise ValueError('owned unused-alias removal receipt required')
    core=copy.deepcopy(value);core['format']=INSTALL_FORMAT
    digest=core['plan'].pop('installation_receipt_sha256',None);identity(digest)
    has_origin='installation_boot_id' in core['plan']
    origin=core['plan'].pop('installation_boot_id',None)
    if has_origin:identity(origin)
    core=validate_install(core);core['format']=FORMAT
    core['plan']['installation_receipt_sha256']=digest
    if has_origin:core['plan']['installation_boot_id']=origin
    return core


def bound_installation(value,installation):
    """Check a fresh owned installation snapshot; this does not authorize writes."""
    value=validate(value)
    if type(installation) is not dict or set(installation)!={'checkpoint','file_sha256'}:
        raise ValueError('fresh owned installation snapshot required')
    original=validate_install(installation['checkpoint']);identity(installation['file_sha256'])
    if (original['status']['phase']!='complete'
        or installation['file_sha256']!=value['plan']['installation_receipt_sha256']
        or original['plan']['boot_id']!=value['plan'].get('installation_boot_id',value['plan']['boot_id'])
        or any(original['plan'][key]!=value['plan'][key] for key in BOUND_FIELDS)):
        raise ValueError('removal must bind the unchanged completed original installation')
    return original


def prepare(*,installation,boot_id,now,utc_now,config,removal_plan,before_file_sha256,after_file_sha256):
    """Create a narrow candidate receipt; keep full config only in local memory."""
    if (not isinstance(config,SourceSpec) or type(removal_plan) is not dict
        or removal_plan.get('operation')!='remove_exact_unreferenced_saved_aliases'):
        raise ValueError('inspected configuration and narrow removal candidate required')
    if type(installation) is not dict or type(installation.get('checkpoint')) is not dict:
        raise ValueError('owned installation snapshot required')
    old=validate_install(installation['checkpoint']);plan=copy.deepcopy(old['plan'])
    candidate=removal_plan.get('configuration')
    checked=review_saved_set(seed_name=plan['seed_name'],definitions=plan['definitions'],
        configuration=candidate,filter_rules='',nat_rules='')
    if (checked['namespace_state']!='absent' or checked['has_external_references']
        or _tree_digest(candidate)!=removal_plan.get('after_tree_sha256')
        or checked['definition_sha256']!=removal_plan.get('definition_sha256')):
        raise ValueError('removal candidate does not match its complete unused alias set')
    from dataclasses import asdict
    plan.update(boot_id=boot_id,prepared_monotonic=now,prepared_utc=utc_now,config=asdict(config),
        before_file_sha256=before_file_sha256,after_file_sha256=after_file_sha256,
        before_tree_sha256=removal_plan['before_tree_sha256'],after_tree_sha256=removal_plan['after_tree_sha256'],
        installation_receipt_sha256=installation['file_sha256'],installation_boot_id=old['plan']['boot_id'])
    value=validate({'format':FORMAT,'plan':plan,'status':{'phase':'prepared',
        'updated_monotonic':now,'updated_utc':utc_now,'observed_file_sha256':None,
        'directory_synced':False,'cache_invalidated':False,'reason':None}})
    bound_installation(value,installation)
    return value


class AliasRemovalFile(AliasInstallFile):
    NAME='alias-remove.json'
    PENDING='alias-remove.pending'
    LOCK='alias-remove.lock'
    ENVELOPE_FORMAT='dnsalias-owned-alias-remove-1'
    PAYLOAD_FORMAT=FORMAT

    def _validate(self,value):
        return validate(value)
