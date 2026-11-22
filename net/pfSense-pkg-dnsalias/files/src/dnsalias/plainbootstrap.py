"""First-hook planning and read-only factory-runtime inspection.

No installer, config/file mutation, reload or automatic recovery entry point.
The existing active-feed runtime checker stays strict about its Python module.
Caller must qualify native source/configuration, exclusive file creation, XML
publication, effective configuration and lifecycle before applying either plan.
"""
import copy
import json
import re
import time

from .processwatch import ProcessLifetimeWatch
from .runtimecontrol import RuntimeControl, RuntimeControlError, option_value

BASENAME='dnsalias_unbound'
FORMAT='dnsalias-owned-plain-hook-1'
FIELDS={'python':'','python_script':BASENAME,'python_order':'post_validator'}


def factory_status(body):
    if type(body) is not bytes or not 1<=len(body)<=4096:raise RuntimeControlError('bounded factory status required')
    try:text=body.decode('ascii')
    except UnicodeError:raise RuntimeControlError('factory status encoding refused') from None
    if any(ord(c)<32 and c!='\n' or ord(c)==127 for c in text):raise RuntimeControlError('factory status control bytes')
    patterns={'version':r'version: ([A-Za-z0-9_.+-]+)','threads':r'threads: ([1-9][0-9]{0,2})',
        'modules':r'modules: ([1-9][0-9]?) \[ ([a-z ]+) \]','uptime':r'uptime: ([0-9]{1,12}) seconds',
        'pid':r'unbound \(pid ([1-9][0-9]{0,9})\) is running\.\.\.'}
    found={}
    for key,pattern in patterns.items():
        rows=re.findall('^'+pattern+'$',text,re.MULTILINE)
        if len(rows)!=1:raise RuntimeControlError('missing or ambiguous factory status')
        found[key]=rows[0]
    count,modules=found['modules'];parts=modules.split()
    if (found['version']!='1.26.1' or parts not in (['iterator'],['validator','iterator'])
        or int(count)!=len(parts) or not 1<=int(found['threads'])<=256 or int(found['pid'])>=2**31):
        raise RuntimeControlError('factory resolver must have no existing Python module')
    return {'version':found['version'],'threads':int(found['threads']),'modules':' '.join(parts),
        'pid':int(found['pid']),'uptime':int(found['uptime'])}


def inspect_factory(control,watch,*,budget_seconds=1):
    """Two equal bounded TLS snapshots, with no Python-empty-option relaxation."""
    if not isinstance(control,RuntimeControl) or not isinstance(watch,ProcessLifetimeWatch):raise ValueError('verified local control and native process watch required')
    if type(budget_seconds) not in (int,float) or not .01<=budget_seconds<=1:raise ValueError('bounded factory inspection budget required')
    start=time.monotonic();deadline=start+budget_seconds
    def read(option=None):
        if time.monotonic()>=deadline or not watch.alive():raise RuntimeControlError('factory inspection lifetime ended')
        return control._read(option,deadline)
    before=factory_status(read())
    if before['pid']!=watch.pid:raise RuntimeControlError('factory control PID mismatch')
    first=option_value('module-config',read('module-config'))
    # In this dedicated no-module path an empty script is required, rather
    # than weakening option_value() for existing active feed callers.
    script=read('python-script')
    second=option_value('module-config',read('module-config'));again=read('python-script')
    after=factory_status(read())
    if (script not in (b'',b'\n') or again!=script or first!=second or first!=before['modules']
        or {k:v for k,v in before.items() if k!='uptime'}!={k:v for k,v in after.items() if k!='uptime'}
        or not 0<=after['uptime']-before['uptime']<=2 or time.monotonic()>=deadline or not watch.alive()):
        raise RuntimeControlError('factory settings changed or an existing script is selected')
    return {'format':'dnsalias-factory-runtime-1','settings':{'module-config':first,'python-script':''},
        'status':after,'process_lifetime_id':watch.lifetime_id,'requests':6,'duration_ms':(time.monotonic()-start)*1000,
        'loaded_source_verified':False,'native_write_authorized':False}


def _source(source_sha256):
    if type(source_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',source_sha256):raise ValueError('explicit owned base source digest required')


def _mapping(parent,key):
    if key not in parent:parent[key]={};return 'absent'
    if parent[key]=='':parent[key]={};return 'empty'
    if type(parent[key]) is not dict:raise ValueError('native package configuration changed')
    return 'mapping'


def _empty_container(parent,key,prior):
    if parent[key]:return
    if prior=='absent':del parent[key]
    elif prior=='empty':parent[key]=''


def prepare(configuration,runtime,*,source_sha256,hook_absent):
    """Plan a first selection only; never adopt even a matching existing file."""
    _source(source_sha256)
    if hook_absent is not True:raise ValueError('first-hook path must be independently verified absent')
    if type(configuration) is not dict or type(configuration.get('unbound')) is not dict:raise ValueError('native enabled resolver configuration required')
    candidate=copy.deepcopy(configuration);cfg=candidate['unbound']
    if 'enable' not in cfg or type(cfg['enable']) is not str:raise ValueError('do not enable a disabled resolver implicitly')
    if any(k in cfg for k in FIELDS):raise ValueError('existing Python configuration requires its own integration')
    if cfg.get('custom_options','')!='':raise ValueError('custom resolver options require effective-configuration qualification')
    prior_packages=_mapping(candidate,'installedpackages');packages=candidate['installedpackages']
    prior_package=_mapping(packages,'dnsalias');package=packages['dnsalias']
    if 'plain_hook_json' in package:raise ValueError('existing bootstrap ownership or package configuration requires inspection')
    expected='validator iterator' if 'dnssec' in cfg else 'iterator'
    if (type(runtime) is not dict or runtime.get('format')!='dnsalias-factory-runtime-1'
        or runtime.get('settings')!={'module-config':expected,'python-script':''}
        or runtime.get('native_write_authorized') is not False):raise ValueError('matching inspected factory runtime required')
    cfg.update(FIELDS)
    package['plain_hook_json']=json.dumps({'format':FORMAT,'basename':BASENAME,'source_sha256':source_sha256,'prior_python':{},'prior_containers':[prior_packages,prior_package]},separators=(',',':'))
    return {'configuration':candidate,'basename':BASENAME,'source_sha256':source_sha256,
        'expected_modules':expected.replace('iterator','python iterator'),'native_write_authorized':False,'file_creation_required':True}


def removal(configuration,*,source_sha256):
    """Narrow plan for an owned selector or already-absent selector, not rollback."""
    _source(source_sha256);candidate=copy.deepcopy(configuration)
    package=candidate.get('installedpackages',{}).get('dnsalias',{})
    raw=package.get('plain_hook_json','')
    if type(raw) is not str or not 0<len(raw)<=4096:raise ValueError('owned plain hook record required')
    value=json.loads(raw);prior=value.get('prior_containers') if type(value) is dict else None
    if (type(prior) is not list or len(prior)!=2 or any(v not in ('absent','empty','mapping') for v in prior)
        or prior[0]!='mapping' and prior[1]!='absent'
        or value!={'format':FORMAT,'basename':BASENAME,'source_sha256':source_sha256,'prior_python':{},'prior_containers':prior}):raise ValueError('plain hook ownership changed')
    if json.loads(package.get('policy_json','[]'))!=[]:raise ValueError('remove saved DNS aliases before plain hook retirement')
    cfg=candidate.get('unbound')
    if type(cfg) is not dict:raise ValueError('native resolver configuration changed')
    selected={k:cfg[k] for k in FIELDS if k in cfg}
    if selected and selected!=FIELDS:raise ValueError('owned Python selection changed; retain user settings')
    for k in FIELDS:cfg.pop(k,None)
    del package['plain_hook_json']
    _empty_container(candidate['installedpackages'],'dnsalias',prior[1]);_empty_container(candidate,'installedpackages',prior[0])
    return {'configuration':candidate,'basename':BASENAME,'native_write_authorized':False,
        'owned_file_retirement_required':True,'already_unselected':not bool(selected)}
