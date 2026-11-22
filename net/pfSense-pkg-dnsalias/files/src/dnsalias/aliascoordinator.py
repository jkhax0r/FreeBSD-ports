"""Explicit offline saved-alias lifecycle; no live target or automatic calls.

Only unused definitions may be installed/removed. The managed collector must be
stopped, with no pending launcher or hook owner. Ordinary PF consumers, table
writers and reboot recovery are deliberately outside this API. A privileged
operator must serialize package start/other management across this transaction.
Uncertain receipts are retained; there is no automatic retry or stale restore.
"""
from contextlib import ExitStack, contextmanager
import hashlib
import os
from pathlib import Path
import secrets
import stat
import sys
import time

from .aliasinstall import AliasInstallFile, prepare as prepare_install
from .aliasremove import AliasRemovalFile, prepare as prepare_removal
from .aliasrefs import plan_saved_install, plan_saved_removal, review_saved_set
from .bootidentity import capture as capture_boot
from .configcache import NativeConfigCache, complete_install, complete_unused_removal
from .configcodec import NativeConfigCodec
from .configpublication import publish_captured_install, publish_captured_unused_removal
from .hookfile import _read
from .pfcapture import PFReferenceCapture
from .reloadlock import SharedReloadLock, ExclusiveConfigLock
from .sourceaudit import SourceAudit, SourceSpec


def _idle(manage, root, data):
    manage.verify(root, data)
    if manage.owned_process(root, data):
        raise ValueError('stop the managed collector before offline alias registration')
    for name in ('trial-launch.json', 'trial-prepare-request', 'observation-prepare-request',
                 'trial-prepare-pending', manage.TRIAL_DIRECTORY):
        if os.path.lexists(data / name):
            raise ValueError('pending or owned hook lifecycle must finish before alias registration')


@contextmanager
def _session(*, root, data, config, locks):
    """Qualify explicit installed package and hold both native guards throughout."""
    if not sys.platform.startswith('freebsd'):
        raise ValueError('qualified native FreeBSD lifecycle required')
    root, data, config, locks = map(Path, (root, data, config, locks))
    if (root != Path(__file__).resolve().parents[1] or not config.is_absolute()
            or config.name != 'config.xml' or not locks.is_absolute()):
        raise ValueError('exact installed package and explicit native targets required')
    import manage
    _idle(manage, root, data)
    manifest = manage.verify(root, data)
    uid, gid = os.geteuid(), os.getegid()
    for directory in (root, data):
        info = directory.stat()
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('private owned installation required')
    boot = capture_boot()['boot_id']
    spec = SourceSpec('firewall_config', str(config), uid, gid, (0o600,), 2*1024*1024)
    owners = tuple(dict.fromkeys((0, uid)))
    parser = Path('/etc/inc/xmlparse.inc'); info = parser.stat()
    with ExitStack() as stack:
        sources = stack.enter_context(SourceAudit([
            SourceSpec('config_codec', str(root/'native/configcodec.php'), uid, gid, (0o600,), 65536),
            SourceSpec('native_xml_parser', str(parser), info.st_uid, info.st_gid,
                       (stat.S_IMODE(info.st_mode),), 100000)], ancestor_uids=owners))
        codec = NativeConfigCodec(sources, helper_sha256=manifest['files']['native/configcodec.php'])
        stack.callback(codec.close)
        pf = stack.enter_context(SourceAudit([
            SourceSpec('pfctl_binary', '/sbin/pfctl', 0, 0, (0o555,), 2*1024*1024)], ancestor_uids=(0,)))
        reload = SharedReloadLock(locks/'filter.lock', expected_uid=uid)
        exclusive = ExclusiveConfigLock(locks/'config.lock', expected_uid=uid)
        stack.callback(reload.close); stack.callback(exclusive.close)
        stack.enter_context(reload); stack.enter_context(exclusive)
        _idle(manage, root, data)
        audit = stack.enter_context(SourceAudit([spec], ancestor_uids=owners))
        raw = _read(audit, audit.files[0], time.monotonic()+1)
        current = codec.decode(raw)['configuration']
        references = PFReferenceCapture(pf, reload, exclusive); references.capture()
        cache = NativeConfigCache(locks/'config.cache', expected_uid=uid, expected_gid=gid)
        stack.callback(cache.close)
        yield dict(manage=manage, root=root, data=data, spec=spec, owners=owners,
                   boot=boot, codec=codec, reload=reload, exclusive=exclusive,
                   audit=audit, current=current, references=references, cache=cache,
                   before=hashlib.sha256(raw).hexdigest())


def _finish(s, journal, installation=None):
    args = (s['audit'], s['exclusive'], s['reload'], s['codec'], journal)
    if installation is None:
        published = publish_captured_install(*args, s['references'], boot_id=s['boot'])
    else:
        published = publish_captured_unused_removal(*args, installation, s['references'], boot_id=s['boot'])
    # Publication consumed the pre-replacement source descriptor. Completion
    # opens the actual new inode under the same uninterrupted native guards.
    fresh = SourceAudit([s['spec']], ancestor_uids=s['owners'])
    args = (fresh, s['exclusive'], s['reload'], s['codec'], journal)
    if installation is None:
        complete = complete_install(*args, s['cache'], boot_id=s['boot'])
    else:
        complete = complete_unused_removal(*args, installation, s['cache'], boot_id=s['boot'])
    return dict(publication_complete=complete['publication_complete'],
                configuration_sha256=complete['configuration_sha256'],
                receipt_sha256=complete['receipt_sha256'], configuration_changed=True,
                filter_reloaded=False, traffic_rules_changed=False,
                cache_was_present=complete['cache']['was_present'],
                reference_capture=s['references'].summary())


def install_unused(*, root, data, config, locks, seed_name, definitions):
    """Explicit one-shot addition. No existing namespace or receipt is adopted."""
    with _session(root=root, data=data, config=config, locks=locks) as s:
        path=s['data']/s['manage'].ALIAS_DIRECTORY
        if os.path.lexists(path):raise ValueError('prior registration requires inspection; no replacement')
        refs=s['references'].arguments()
        if set(definitions).intersection(n.lower() for n in refs['existing_tables']):
            raise ValueError('existing PF table namespace cannot be adopted')
        plan=plan_saved_install(seed_name=seed_name, definitions=definitions,
            configuration=s['current'], filter_rules=refs['filter_rules'], nat_rules=refs['nat_rules'])
        rendered=s['codec'].encode(plan['configuration'])
        value=prepare_install(installation_id=secrets.token_hex(16), boot_id=s['boot'],
            now=time.monotonic(), utc_now=time.time(), config=s['spec'], install_plan=plan,
            seed_name=seed_name, definitions=definitions, before_file_sha256=s['before'],
            after_file_sha256=rendered['xml_sha256'])
        s['manage'].prepare_alias_directory(value, root=s['root'], data=s['data'])
        with AliasInstallFile(path, expected_uid=os.geteuid()) as journal:
            return _finish(s, journal) | {'operation':'install_unused', 'names':sorted(definitions)}


def remove_unused(*, root, data, config, locks):
    """Remove an exact owned unused set under a freshly captured operation boot."""
    with _session(root=root, data=data, config=config, locks=locks) as s:
        owned=s['manage'].inspect_alias_directory(s['root'], s['data'])
        if (owned is None or owned['pending_file'] or owned['removal'] is not None
                or owned['installation'] is None):
            raise ValueError('one untouched completed installation is required')
        value=owned['installation']['checkpoint']; old=value['plan']
        if value['status']['phase']!='complete':
            raise ValueError('incomplete installation requires inspection')
        refs=s['references'].arguments()
        if set(old['definitions']).intersection(n.lower() for n in refs['existing_tables']):
            raise ValueError('retire registered PF tables before unused alias removal')
        plan=plan_saved_removal(seed_name=old['seed_name'], definitions=old['definitions'],
            configuration=s['current'], filter_rules=refs['filter_rules'], nat_rules=refs['nat_rules'],
            prior_alias_container=old['prior_alias_container'], prior_alias_list=old['prior_alias_list'])
        rendered=s['codec'].encode(plan['configuration'])
        value=prepare_removal(installation=owned['installation'], boot_id=s['boot'],
            now=time.monotonic(), utc_now=time.time(), config=s['spec'], removal_plan=plan,
            before_file_sha256=s['before'], after_file_sha256=rendered['xml_sha256'])
        path=s['data']/s['manage'].ALIAS_DIRECTORY
        with AliasInstallFile(path, expected_uid=os.geteuid()) as installation:
            with AliasRemovalFile(path, expected_uid=os.geteuid()) as journal:
                journal.save(value, expected_digest=None)
                return _finish(s, journal, installation) | {'operation':'remove_unused', 'names':sorted(old['definitions'])}


class SavedAliasAuthority:
    """Read-only authority for a registered policy identity, never old leases.

    The durable completed receipt owns exact saved definitions across boots.
    Each object binds one fresh boot; acquisition still requires independently
    verified EMPTY kernel membership. No stale membership is adopted/restored.
    This does not qualify an ordinary rule's source scope or authorize a write.
    No active caller uses this class until its registered-table lifecycle passes.
    """
    def __init__(self,*,root,data,config,table):
        self.root,self.data,self.config=map(Path,(root,data,config))
        if (not sys.platform.startswith('freebsd') or self.root!=Path(__file__).resolve().parents[1]
            or not self.config.is_absolute() or self.config.name!='config.xml'):
            raise ValueError('exact installed package and explicit native configuration required')
        import manage
        self.manage=manage;self.uid=os.geteuid();self.gid=os.getegid()
        for directory in (self.root,self.data):
            info=directory.stat()
            if info.st_uid!=self.uid or stat.S_IMODE(info.st_mode)!=0o700:raise ValueError('private owned package directories required')
        self.manifest=manage.verify(self.root,self.data)
        owned=self._owned();value=owned['checkpoint'];plan=value['plan']
        if (type(table) is not str or table not in plan['definitions'] or table==plan['seed_name']
            or plan['config']['path']!=str(self.config)):
            raise ValueError('one owned policy identity and exact receipt configuration required')
        self.table=table;self.digest=owned['file_sha256'];self.plan=plan
        self.boot=capture_boot()['boot_id'];self.creator_pid=os.getpid()

    def _owned(self):
        aliases=self.manage.inspect_alias_directory(self.root,self.data)
        if (aliases is None or aliases['pending_file'] or aliases['removal'] is not None
            or aliases['installation'] is None
            or aliases['installation']['checkpoint']['status']['phase']!='complete'):
            raise ValueError('complete unchanged registered alias ownership required')
        return aliases['installation']

    def review(self,reload_guard,config_guard):
        """Fresh native tree under the caller's continuously held native guards."""
        return self._review(reload_guard,config_guard)

    def _cleanup_binding(self,fence):
        from .membershipgate import ExclusiveMembershipGate
        from .trialtable import _Receipt as TableReceipt
        if (type(fence) is not ExclusiveMembershipGate or not fence.disarmed or not fence.valid()
            or self.creator_pid!=os.getpid()
            or (fence.descriptor['uid'],fence.descriptor['gid'])!=(self.uid,self.gid)):
            raise ValueError('original process and held permanently disarmed membership gate required')
        with TableReceipt(fence.path.parent,expected_uid=self.uid) as store:record=store.read()
        if record is None:raise ValueError('acquired table binding required for deletion-only review')
        value=record['checkpoint']
        if (value.get('phase')!='acquired' or value.get('rule',{}).get('table')!=self.table
            or value.get('registration_receipt_sha256')!=self.digest
            or value.get('registration_boot_id')!=self.boot
            or value.get('membership_gate')!=dict(fence.descriptor)):
            raise ValueError('exact table/installation/session binding required for deletion-only review')
        return record

    def review_cleanup(self,reload_guard,config_guard,fence):
        """Deletion-only review despite a changed clock-derived boot fingerprint.

        An object cannot survive a real reboot in its original process. Require
        that process plus its held exclusive original-inode disarmed gate and
        exact acquired-table receipt. Saved ownership/source/config guards still
        apply. This authorizes no addition, lease recovery or table acquisition.
        """
        return self._review(reload_guard,config_guard,cleanup_fence=fence)

    def _review(self,reload_guard,config_guard,*,cleanup_fence=None):
        def guarded():
            if (type(reload_guard) is not SharedReloadLock or type(config_guard) is not ExclusiveConfigLock
                or not reload_guard.valid() or not config_guard.valid()
                or reload_guard.identity==config_guard.identity
                or reload_guard.path.name!='filter.lock' or config_guard.path.name!='config.lock'
                or reload_guard.path.parent!=config_guard.path.parent):
                raise ValueError('continuous native filter/config guards required')
        guarded()
        if self.manage.verify(self.root,self.data)!=self.manifest or self._owned()['file_sha256']!=self.digest:
            raise ValueError('registered installation changed; no adoption')
        binding=None
        if cleanup_fence is None:
            if capture_boot()['boot_id']!=self.boot:raise ValueError('registered writer boot lifetime ended')
        else:binding=self._cleanup_binding(cleanup_fence)
        plan=self.plan;spec=SourceSpec(**(plan['config']|{'modes':tuple(plan['config']['modes'])}))
        if (spec.uid,spec.gid)!=(self.uid,self.gid):raise ValueError('registered configuration ownership differs')
        owners=tuple(dict.fromkeys((0,self.uid)));parser=Path('/etc/inc/xmlparse.inc');info=parser.stat()
        with SourceAudit([
            SourceSpec('config_codec',str(self.root/'native/configcodec.php'),self.uid,self.gid,(0o600,),65536),
            SourceSpec('native_xml_parser',str(parser),info.st_uid,info.st_gid,(stat.S_IMODE(info.st_mode),),100000)],ancestor_uids=owners) as sources:
            codec=NativeConfigCodec(sources,helper_sha256=self.manifest['files']['native/configcodec.php'])
            try:
                with SourceAudit([spec],ancestor_uids=owners) as audit:
                    raw=_read(audit,audit.files[0],time.monotonic()+1)
                    current=codec.decode(raw)['configuration']
                    checked=review_saved_set(seed_name=plan['seed_name'],definitions=plan['definitions'],
                        configuration=current,filter_rules='',nat_rules='')
                    if checked['namespace_state']!='exact':raise ValueError('saved alias definitions changed; no repair')
                    guarded();audit.audit()
                    if self._owned()['file_sha256']!=self.digest:raise ValueError('registration changed during native review')
                    if cleanup_fence is not None and self._cleanup_binding(cleanup_fence)!=binding:
                        raise ValueError('deletion-only session binding changed during native review')
                    return {'table':self.table,'installation_receipt_sha256':self.digest,
                        'definition_sha256':plan['definition_sha256'],'configuration_sha256':audit.hashes['firewall_config'],
                        'boot_id':self.boot,'origin_boot_id':plan['boot_id'],
                        'saved_external_references':checked['has_external_references'],
                        'membership_recovery_authorized':False}|({
                            'cleanup_only':True,'boot_identity_rechecked':False,
                            'lifetime_basis':'same_process_and_bound_exclusive_disarmed_gate'} if cleanup_fence is not None else {})
            finally:codec.close()
