"""Seed-to-native-registry planning and explicit native publication.

Ordinary rules keep the same table names. Only exact package-owned saved
definitions and the owned unused seed are removed. The publisher must first
qualify/install the native entry, stop owners, capture fresh config/PF state
and hold native config/filter guards. A plan is not write authorization.
The native package coordinator calls this only during fresh setup, explicit
stopped source Apply or owned uninstall. Catalog resync does not migrate.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from .aliasrefs import review
from .checkpointfile import CheckpointFile
from .ipc import strict_pairs,invalid_number
from .leases import Policy
from .lifecycle import guarded

SEED='da_dnsalias_seed'
MODE='registered-v1'
SEED_DEFINITION={'name':SEED,'type':'host','descr':'DNS Alias internal empty definition; never populate','address':'','detail':''}


class MigrationFile(CheckpointFile):
    NAME='native-migration.json';PENDING='native-migration.pending';LOCK='native-migration.lock'
    ENVELOPE_FORMAT='dnsalias-native-migration-envelope-1';PAYLOAD_FORMAT='dnsalias-native-migration-1'


def ready(data):
    data=Path(data)
    if os.path.lexists(data/MigrationFile.PENDING):raise ValueError('Pending native registry migration requires inspection')
    if os.path.lexists(data/MigrationFile.NAME):
        with MigrationFile(data,expected_uid=os.geteuid()) as journal:
            if journal.read()['checkpoint'].get('phase')!='complete':raise ValueError('Incomplete native registry migration requires inspection')


def policies(raw):
    if type(raw) is not str or len(raw)>262144:raise ValueError('Bounded saved policy JSON required')
    value=json.loads(raw,object_pairs_hook=strict_pairs,parse_constant=invalid_number)
    if type(value) is not list or len(value)>127:raise ValueError('Saved policy list required')
    seen=set()
    for row in value:
        if (type(row) is not dict or set(row)!={'name','names','enabled'} or type(row['name']) is not str
            or not re.fullmatch('[a-z][a-z0-9_]{0,22}',row['name']) or row['name'].startswith(('seed','mvp_'))
            or row['name'] in seen or type(row['enabled']) is not bool or type(row['names']) is not list
            or any(type(n) is not str for n in row['names']) or len(set(row['names']))!=len(row['names'])):
            raise ValueError('Invalid saved DNS policy')
        parsed=Policy(row['name'],tuple(row['names']))
        if parsed.patterns!=tuple(row['names']):raise ValueError('Canonical saved DNS patterns required')
        seen.add(row['name'])
    return value


def plan(configuration,filter_rules,nat_rules,*,reserved_names=()):
    if type(configuration) is not dict:raise ValueError('Fresh native configuration tree required')
    if type(reserved_names) not in (tuple,list) or len(reserved_names)>10000 or any(type(n) is not str for n in reserved_names):
        raise ValueError('Bounded native reserved namespace required')
    candidate=copy.deepcopy(configuration);installed=candidate.setdefault('installedpackages',{})
    if type(installed) is not dict:raise ValueError('Native package container changed')
    package=installed.setdefault('dnsalias',{})
    if type(package) is not dict:raise ValueError('DNS Alias package container changed')
    raw=package.get('policy_json','[]');saved=policies(raw);tables=tuple('da_'+row['name'] for row in saved)
    mode=package.get('native_alias_mode','legacy')
    if mode not in ('legacy',MODE):raise ValueError('Unknown native alias integration mode')
    container=candidate.get('aliases',{})
    if container in ('',None):container={}
    if type(container) is not dict:raise ValueError('Native alias container changed')
    aliases=container.get('alias',[])
    if aliases in ('',None):aliases=[]
    if type(aliases) is not list or len(aliases)>10000:raise ValueError('Bounded native saved aliases required')
    by={}
    for alias in aliases:
        if type(alias) is not dict or type(alias.get('name')) is not str or alias['name'].lower() in by:
            raise ValueError('Native alias identity changed or duplicated')
        by[alias['name'].lower()]=alias
    if mode==MODE:
        if any(name in by for name in (*tables,SEED)) or package.get('seed_json','')!='':
            raise ValueError('Registered mode contains legacy aliases or seed metadata')
        return {'configuration':candidate,'tables':tables,'removed_native_aliases':[],'seed_removed':False,
                'already_registered':True,'traffic_rules_changed':False,'native_write_authorized':False}
    occupied={name.lower() for name in reserved_names}
    if any(name in occupied for name in tables):raise ValueError('Foreign reserved table namespace collision')
    for row in saved:
        expected={'name':'da_'+row['name'],'type':'host','descr':'DNS Alias: '+row['name'],'address':SEED,'detail':''}
        if by.get(expected['name'])!=expected:raise ValueError('Complete exact owned native alias set required; no adoption or repair')
    seed_raw=package.get('seed_json','')
    if seed_raw!='':
        if type(seed_raw) is not str or len(seed_raw)>4096 or json.loads(seed_raw,object_pairs_hook=strict_pairs)!={'format':'dnsalias-native-seed-1','alias':SEED_DEFINITION}:
            raise ValueError('Seed ownership record changed')
        if by.get(SEED)!=SEED_DEFINITION:raise ValueError('Owned seed definition changed')
    elif saved or SEED in by:raise ValueError('Existing seed requires explicit ownership; no adoption')
    remove=set(tables)|({SEED} if seed_raw else set())
    kept=[row for row in aliases if row['name'] not in remove]
    if 'aliases' in candidate and type(candidate['aliases']) is dict and 'alias' in candidate['aliases']:
        if kept:candidate['aliases']['alias']=kept
        else:
            del candidate['aliases']['alias']
            if not candidate['aliases']:del candidate['aliases']
    package.pop('seed_json',None);package['native_alias_mode']=MODE
    package.setdefault('policy_json',raw)
    references=copy.deepcopy(candidate);references.pop('revision',None)
    result=review((SEED,),configuration=references,filter_rules=filter_rules,nat_rules=nat_rules)
    if result['has_mentions']:raise ValueError('Seed still has an external consumer; preserve it')
    return {'configuration':candidate,'tables':tables,'removed_native_aliases':[row['name'] for row in aliases if row['name'] in remove],
            'seed_removed':bool(seed_raw),'already_registered':False,'traffic_rules_changed':False,'native_write_authorized':False}


def retire_plan(configuration):
    candidate=copy.deepcopy(configuration);package=candidate.get('installedpackages',{}).get('dnsalias',{})
    if type(package) is not dict or policies(package.get('policy_json','[]')):raise ValueError('Delete saved DNS aliases before retiring the native registry')
    mode=package.get('native_alias_mode','legacy')
    if mode not in ('legacy',MODE):raise ValueError('Unknown native alias mode')
    if package.get('seed_json','')!='':raise ValueError('Legacy seed ownership remains; preserve its lifecycle')
    if mode==MODE:package.pop('native_alias_mode')
    return {'configuration':candidate,'tables':(),'removed_native_aliases':[],'seed_removed':False,
            'already_registered':mode=='legacy','traffic_rules_changed':False,'native_write_authorized':False}


@guarded(mode='write',control=True)
def operate(*,action='migrate',root=None,data=None,config=None,locks=None):
    """Explicit native transaction; no PF, DNS, service or core-source writes."""
    from .registryentry import inspect as inspect_entry,ROOT,DATA,ENTRY
    from .nativebootstrap import NATIVE_SOURCES
    from .sourceaudit import SourceAudit,SourceSpec
    from .aliascoordinator import _session
    from .hookfile import _read
    root,data=Path(root or ROOT),Path(data or DATA);config=Path(config or '/cf/conf/config.xml');locks=Path(locks or '/tmp')
    if (not sys.platform.startswith('freebsd') or root!=ROOT or root!=Path(__file__).resolve().parents[1]
        or data!=DATA or config!=Path('/cf/conf/config.xml') or locks!=Path('/tmp') or action not in ('migrate','retire')):
        raise ValueError('Exact installed native registry transaction required')
    if any(os.path.lexists(data/name) for name in ('collector.pid','alias-service.pid','trial-launch.json','trial-prepare-request','observation-prepare-request')):
        raise ValueError('Stop and verify all owners before native registry migration')
    ready(data);pending=config.with_name('config.xml.dnsalias-registry.pending')
    if os.path.lexists(pending):raise ValueError('Pending native configuration publication requires inspection')
    entry=inspect_entry(root,data,ENTRY)
    if not entry['installed'] or not entry['matches_source']:raise ValueError('Matching complete owned native registry entry required')
    entry_sha=entry['receipt']['checkpoint']['entry_sha256']
    specs=[SourceSpec('registry_native_'+str(i),path,0,0,(0o644,),1000000) for i,path in enumerate(NATIVE_SOURCES)]
    with SourceAudit(specs,ancestor_uids=(0,)) as native:
        if any(native.hashes[spec.name]!=NATIVE_SOURCES[spec.path] for spec in specs):raise ValueError('Qualified native registry API changed')
        # A native config read can legitimately create config.cache. Perform
        # it before the publisher captures cache identity, and bind its result
        # to the exact fresh XML captured under the native guards below.
        php="$before=hash_file('sha256','/cf/conf/config.xml');require_once '/etc/inc/config.inc';require_once '/etc/inc/util.inc';$after=hash_file('sha256','/cf/conf/config.xml');if($before!==$after)throw new RuntimeException('Configuration changed during registry read');echo json_encode(['configuration_sha256'=>$after,'reserved'=>array_keys(get_reserved_table_names())]);"
        p=subprocess.run(['/usr/local/bin/php','-r',php],capture_output=True,text=True,timeout=3)
        if p.returncode or p.stderr or len(p.stdout)>1048576:raise ValueError('Native reserved namespace unavailable')
        namespace=json.loads(p.stdout)
        with _session(root=root,data=data,config=config,locks=locks) as session:
            if namespace['configuration_sha256']!=session['before']:raise ValueError('Native registry namespace snapshot changed before publication')
            reference=session['references'].arguments()
            reserved=namespace['reserved'];current=session['current']
            proposed=plan(current,reference['filter_rules'],reference['nat_rules'],reserved_names=reserved) if action=='migrate' else retire_plan(current)
            if proposed['configuration']==current:return {'configuration_unchanged':True,'mode':current.get('installedpackages',{}).get('dnsalias',{}).get('native_alias_mode','legacy')}
            rendered=session['codec'].encode(proposed['configuration']);raw=rendered['xml'].encode() if isinstance(rendered['xml'],str) else rendered['xml']
            with MigrationFile(data,expected_uid=os.geteuid()) as journal:
                old=journal.read()
                if old is not None and old['checkpoint'].get('phase')!='complete':raise ValueError('Prior native migration outcome requires inspection')
                value={'format':MigrationFile.PAYLOAD_FORMAT,'operation':action,'phase':'prepared','before_sha256':session['before'],
                    'after_sha256':hashlib.sha256(raw).hexdigest(),'entry_sha256':entry_sha,'tables':list(proposed['tables'])}
                digest=journal.save(value,expected_digest=old['file_sha256'] if old else None)
                fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    os.fchmod(fd,0o600);view=memoryview(raw)
                    while view:
                        n=os.write(fd,view)
                        if n<=0:raise OSError('Short native registry configuration publication')
                        view=view[n:]
                    os.fsync(fd)
                finally:os.close(fd)
                native.audit();session['audit'].audit();session['references'].arguments()
                again=inspect_entry(root,data,ENTRY)
                if not again['installed'] or not again['matches_source'] or again['receipt']['checkpoint']['entry_sha256']!=entry_sha:
                    raise ValueError('Native registry entry changed before configuration publication')
                os.replace(pending,config);directory=os.open(config.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:os.fsync(directory)
                finally:os.close(directory)
                value['phase']='replaced';digest=journal.save(value,expected_digest=digest);session['cache'].invalidate()
                with SourceAudit([session['spec']],ancestor_uids=session['owners']) as fresh:
                    observed=_read(fresh,fresh.files[0],time.monotonic()+1)
                    if hashlib.sha256(observed).hexdigest()!=value['after_sha256'] or session['codec'].decode(observed)['configuration']!=proposed['configuration']:
                        raise ValueError('Native registry configuration readback differs; inspect outcome')
                    # Native config readers can rebuild their cache after the
                    # publisher releases config.lock. Keep reloads excluded.
                    session['exclusive'].__exit__()
                    p=subprocess.run(['/usr/local/bin/php',str(root/'native/policies.php')],capture_output=True,text=True,timeout=3)
                    if p.returncode or p.stderr or len(p.stdout)>262144:raise ValueError('Native registry policy readback unavailable; inspect published outcome')
                    snapshot=json.loads(p.stdout)
                    if snapshot!={'format':'dnsalias-saved-aliases-1','policies':policies(proposed['configuration']['installedpackages']['dnsalias'].get('policy_json','[]'))}:
                        raise ValueError('Native registry policy readback differs; inspect outcome')
                    fresh.audit();native.audit()
                value['phase']='complete';journal.save(value,expected_digest=digest)
                return {'configuration_changed':True,'mode':MODE if action=='migrate' else 'legacy','tables':list(proposed['tables']),
                    'seed_removed':proposed['seed_removed'],'ordinary_rules_preserved':True,'pf_changed':False,'dns_changed':False,
                    'native_core_changed':False,'automatic_retry':False,'entry_sha256':entry_sha}
