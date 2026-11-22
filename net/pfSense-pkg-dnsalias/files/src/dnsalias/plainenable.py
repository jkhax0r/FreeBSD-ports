"""First plain-Unbound setup during an explicit native service enable/start.

Existing Python selections are untouched. This creates only a previously absent
owned base, then applies the native resolver configuration once. An incomplete
setup or failed Apply requires inspection, never an automatic retry.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

from .lifecycle import guarded
from .sourceaudit import SourceAudit,SourceSpec


def needs_setup(raw):
    root=ET.fromstring(raw)
    if root.tag!='pfsense' or len(root.findall('unbound'))!=1:
        raise ValueError('one native DNS Resolver configuration required')
    cfg=root.find('unbound')
    # An existing selection, including partial/disabled settings, belongs to
    # its current owner. The ordinary target checker qualifies it separately.
    if any(cfg.find(name) is not None for name in ('python','python_script','python_order')):return False
    if cfg.find('enable') is None:raise ValueError('enable DNS Resolver before enabling DNS Alias')
    return True


@guarded(control=True)
def ensure(root,data):
    import manage
    from .aliasservice import process,target
    from .plainsetup import operate
    root,data=Path(root),Path(data)
    if not sys.platform.startswith('freebsd') or os.geteuid()!=0 or root!=Path('/usr/local/libexec/dnsalias'):
        raise ValueError('installed native root service required')
    manifest=manage.verify(root,data)
    with SourceAudit([SourceSpec('firewall_config','/cf/conf/config.xml',0,0,(0o600,),2*1024*1024)],ancestor_uids=(0,)) as config:
        raw=Path('/cf/conf/config.xml').read_bytes();config.audit()
    if not needs_setup(raw):return {'first_hook_created':False,'existing_selection_preserved':True}
    include=Path('/var/unbound/dnsalias_unbound_include.inc')
    # Native Apply can execute this optional PHP include as root. An existing
    # include is not part of the owned first-hook setup and must not be loaded.
    if os.path.lexists(include):raise ValueError('unowned plain-hook native include requires inspection')
    if process() is not None or manage.inspect_trial_directory(root,data) is not None:
        raise ValueError('prior alias activity requires inspection before first-hook setup')
    specs=[SourceSpec('native_services','/etc/inc/services.inc',0,0,(0o644,),1048576),
        SourceSpec('native_apply',str(root/'native/policies.php'),0,0,(0o600,),65536)]
    with SourceAudit(specs,ancestor_uids=(0,)) as sources:
        if sources.hashes['native_services']!='a831afce1d8d54e9689fa262c26c685fae065444aec8963627cc8916093bba04':
            raise ValueError('native resolver Apply changed; first enable requires qualification')
        if sources.hashes['native_apply']!=manifest['files']['native/policies.php']:
            raise ValueError('owned resolver Apply helper changed')
        operate('review',root=root,data=data)
        operate('install',root=root,data=data)
        sources.audit()
        if os.path.lexists(include):raise ValueError('plain-hook native include appeared; inspect saved first-hook setup')
        # A single explicit native Apply after the first owned selection. The
        # helper suppresses the unrelated DHCP restart; it creates no PF rules.
        applied=subprocess.run(['/usr/local/bin/php','-d','memory_limit=128M','-d','display_errors=stderr','-d','log_errors=0',str(root/'native/policies.php'),'plain-first-apply'],
            capture_output=True,text=True,timeout=45)
        sources.audit()
        if applied.returncode or len(applied.stdout)>4096 or len(applied.stderr)>8192:
            raise RuntimeError('First hook is saved; native resolver Apply needs inspection before retrying')
        if json.loads(applied.stdout)!={'return':0}:
            raise RuntimeError('First hook is saved; native resolver Apply outcome needs inspection')
    ready=target(root,data)
    if ready['mode']!='plain':raise ValueError('first-hook runtime differs from the saved plain selection')
    return {'first_hook_created':True,'native_resolver_apply_completed':True,'rules_created':False,'foreign_hook_adopted':False}
