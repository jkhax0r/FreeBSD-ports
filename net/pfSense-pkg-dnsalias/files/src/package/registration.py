"""Owned native menu/service configuration plans for the package installer.

Pure tree transformations only: no default files, configuration publication,
service activation, DNS setup, alias/rule creation or recovery. A native caller
must publish under qualified config/filter locks with a durable receipt and
invalidate/read back the native cache. Missing native menu/service metadata on
removal is allowed because pfSense removes it before custom deinstall hooks.
Matching pre-existing entries without our marker are never adopted.
"""
import copy
import json
from urllib.parse import urlsplit

FORMAT = 'dnsalias-native-gui-1'
MARKER = 'registration_json'
MENU = {'name':'DNS Aliases','section':'Firewall','url':'/dnsalias_status.php?view=aliases'}
SERVICE = {'name':'dnsalias','description':'DNS Alias: trusted DNS destination tables and activity',
    'rcfile':'dnsalias.sh','executable':'',
    'custom_php_service_status_command':"isvalidpid('/var/db/dnsalias/collector.pid') && (config_get_path('installedpackages/dnsalias/policy_json','[]') === '[]' || isvalidpid('/var/db/dnsalias/alias-service.pid'))"}


def _clone(configuration):
    if type(configuration) is not dict or not configuration:raise ValueError('nonempty native configuration required')
    raw=json.dumps(configuration,allow_nan=False,separators=(',',':'))
    if len(raw.encode())>8*1024*1024:raise ValueError('bounded native configuration required')
    return copy.deepcopy(configuration)


def _containers(configuration):
    packages=configuration.get('installedpackages',{})
    if type(packages) is not dict:raise ValueError('native package container changed')
    package=packages.get('dnsalias',{})
    if type(package) is not dict:raise ValueError('DNS Alias settings container changed')
    rows={}
    for key in ('menu','service'):
        value=packages.get(key,[])
        if type(value) is not list or len(value)>4096 or any(type(row) is not dict for row in value):raise ValueError('bounded native '+key+' list required')
        rows[key]=value
    return packages,package,rows


def _ours(key,row):
    name=row.get('name','')
    if type(name) is not str:raise ValueError('native entry name changed')
    if key=='service':return name.casefold()=='dnsalias'
    url=row.get('url','')
    if type(url) is not str or len(url)>8192:raise ValueError('native menu URL changed')
    # A second label pointing at the same page is also a conflicting entry.
    return name.casefold()==MENU['name'].casefold() or urlsplit(url).path.lstrip('/').casefold()=='dnsalias_status.php'


def _selected(key,rows,*,owned,allow_missing=False):
    matches=[row for row in rows if _ours(key,row)]
    expected=MENU if key=='menu' else SERVICE
    if not owned:
        if matches:raise ValueError('existing unowned native '+key+' entry; no adoption')
    elif len(matches)>1 or matches and matches[0]!=expected:raise ValueError('owned native '+key+' entry changed')
    elif not matches and not allow_missing:raise ValueError('owned native '+key+' entry missing')
    return matches


def _pairs(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate GUI ownership field')
        value[key]=item
    return value


def _record(package):
    raw=package.get(MARKER)
    if raw is None:return None
    if type(raw) is not str or not 0<len(raw)<=8192:raise ValueError('bounded GUI ownership marker required')
    try:value=json.loads(raw,object_pairs_hook=_pairs)
    except (ValueError,TypeError):raise ValueError('GUI ownership marker invalid') from None
    if (type(value) is not dict or set(value)!={'format','menu','service','prior'} or value['format']!=FORMAT
        or value['menu']!=MENU or value['service']!=SERVICE or type(value['prior']) is not dict
        or set(value['prior'])!={'installedpackages','dnsalias','menu','service'}
        or any(type(v) is not bool for v in value['prior'].values())
        or not value['prior']['installedpackages'] and any(value['prior'][key] for key in ('dnsalias','menu','service'))):
        raise ValueError('GUI ownership marker changed')
    return value


def _settings(package):
    settings=package.get('config')
    if (type(settings) is not list or len(settings)!=1 or type(settings[0]) is not dict
        or settings[0].get('enable') not in ('on','off')):raise ValueError('owned global Enable setting changed')
    return settings


def inspect(configuration):
    """Return bounded registration evidence, never private config contents."""
    current=_clone(configuration);packages,package,rows=_containers(current);record=_record(package)
    counts={key:len([row for row in value if _ours(key,row)]) for key,value in rows.items()}
    if record is None:
        for key,value in rows.items():_selected(key,value,owned=False)
        if 'config' in package:raise ValueError('existing global service settings require explicit migration')
        return {'registered':False,'eligible':True,'configuration_changed':False,'services_started':False,'rules_created':False}
    for key,value in rows.items():_selected(key,value,owned=True,allow_missing=True)
    settings=_settings(package)
    return {'registered':True,'menu_present':bool(counts['menu']),'service_present':bool(counts['service']),
        'enabled':settings[0]['enable']=='on','configuration_changed':False,'services_started':False,'rules_created':False}


def install(configuration):
    """Create a Firewall menu, Status Services entry and disabled global setting."""
    candidate=_clone(configuration);packages,package,rows=_containers(candidate);record=_record(package)
    if record is not None:
        for key,value in rows.items():_selected(key,value,owned=True)
        _settings(package)
        return {'configuration':candidate,'changed':False,'services_started':False,'rules_created':False}
    inspect(candidate)
    prior={'installedpackages':'installedpackages' in candidate,'dnsalias':'dnsalias' in packages,
        'menu':'menu' in packages,'service':'service' in packages}
    candidate.setdefault('installedpackages',{})['dnsalias']=package
    packages=candidate['installedpackages']
    for key,expected in (('menu',MENU),('service',SERVICE)):packages[key]=rows[key]+[copy.deepcopy(expected)]
    package['config']=[{'enable':'off'}]
    package[MARKER]=json.dumps({'format':FORMAT,'menu':MENU,'service':SERVICE,'prior':prior},sort_keys=True,separators=(',',':'))
    return {'configuration':candidate,'changed':True,'enabled':False,'services_started':False,'rules_created':False}


def migrate(configuration):
    """Explicit legacy conversion; the caller must prove owned UI and rc files.

    This is deliberately separate from fresh install and never accepts a
    changed/duplicate native entry. Existing Enable and package settings stay
    byte-for-byte equivalent in the decoded configuration tree.
    """
    candidate=_clone(configuration);packages,package,rows=_containers(candidate)
    if _record(package) is not None:raise ValueError('existing GUI registration requires inspection, not migration')
    settings=_settings(package)
    selected={key:_selected(key,value,owned=True,allow_missing=key=='menu') for key,value in rows.items()}
    # The legacy deployment already owns its namespace and entries. There is
    # no earlier empty-container snapshot to restore on uninstall. Prune only
    # containers that become empty; all unrelated rows/settings still remain.
    # Keeping an empty associative namespace cannot round-trip through native
    # pfSense XML (it becomes a string), so it must not survive removal.
    prior={key:False for key in ('installedpackages','dnsalias','menu','service')}
    if not selected['menu']:packages['menu']=rows['menu']+[copy.deepcopy(MENU)]
    package[MARKER]=json.dumps({'format':FORMAT,'menu':MENU,'service':SERVICE,'prior':prior},sort_keys=True,separators=(',',':'))
    return {'configuration':candidate,'changed':True,'enabled':settings[0]['enable']=='on',
        'menu_added':not bool(selected['menu']),'services_started':False,'rules_created':False}


def remove(configuration):
    """Remove exact owned entries; preserve later unrelated settings and rules."""
    candidate=_clone(configuration);packages,package,rows=_containers(candidate);record=_record(package)
    if record is None:raise ValueError('owned GUI registration required before removal')
    settings=_settings(package)
    for key,value in rows.items():
        selected=_selected(key,value,owned=True,allow_missing=True)
        if selected:packages[key]=[row for row in value if row is not selected[0]]
        if not packages.get(key) and not record['prior'][key]:packages.pop(key,None)
    del settings[0]['enable']
    if not settings[0]:del package['config']
    del package[MARKER]
    if not package and not record['prior']['dnsalias']:packages.pop('dnsalias',None)
    if not packages and not record['prior']['installedpackages']:candidate.pop('installedpackages',None)
    return {'configuration':candidate,'changed':True,'services_started':False,'rules_created':False}
