"""Delete one unused saved DNS alias; preserve every ordinary rule.

The UI first reviews references, disables that alias, and waits for its empty
writer acknowledgement. The final local transaction checks fresh configuration,
all PF anchors and empty membership again under native config/filter locks.
Receipts contain hashes and operation state, without configuration contents.
"""
import argparse
from contextlib import ExitStack
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from .aliasrefs import review
from .checkpointfile import CheckpointFile
from .configcache import NativeConfigCache
from .configcodec import NativeConfigCodec
from .hookfile import _read
from .leases import Policy
from .pfcapture import PFReferenceCapture
from .pfapi import NativePFTables
from .reloadlock import SharedReloadLock, ExclusiveConfigLock
from .sourceaudit import SourceAudit, SourceSpec
from .lifecycle import current,guarded


class DeleteFile(CheckpointFile):
    NAME='policy-delete.json';PENDING='policy-delete.pending';LOCK='policy-delete.lock'
    ENVELOPE_FORMAT='dnsalias-policy-delete-envelope-1';PAYLOAD_FORMAT='dnsalias-policy-delete-1'


def ready(data):
    data=Path(data)
    if (data/DeleteFile.PENDING).exists():raise ValueError('pending alias deletion requires inspection')
    if (data/DeleteFile.NAME).exists():
        with DeleteFile(data,expected_uid=os.geteuid()) as journal:
            if journal.read()['checkpoint'].get('phase')!='complete':raise ValueError('incomplete alias deletion requires inspection')


def plan(name,configuration,filter_rules,nat_rules,*,remove=False,stopped=False):
    if type(stopped) is not bool or stopped and not remove:raise ValueError('explicit stopped removal required')
    if type(name) is not str or not re.fullmatch('[a-z][a-z0-9_]{0,22}',name):raise ValueError('saved alias name required')
    candidate=copy.deepcopy(configuration);table='da_'+name
    package=candidate.get('installedpackages',{}).get('dnsalias',{})
    policies=json.loads(package.get('policy_json','[]'))
    if type(policies) is not list or len(policies)>127:raise ValueError('bounded saved policies required')
    selected=[p for p in policies if p.get('name')==name]
    if len(selected)!=1:raise ValueError('saved DNS alias not found')
    p=selected[0]
    if set(p)!={'name','names','enabled'} or type(p['enabled']) is not bool or type(p['names']) is not list:raise ValueError('saved alias changed')
    Policy(p['name'],tuple(p['names']))
    aliases=candidate.get('aliases',{}).get('alias',[])
    if type(aliases) is not list:raise ValueError('native alias list required')
    rows=[a for a in aliases if str(a.get('name','')).lower()==table]
    mode=package.get('native_alias_mode','legacy')
    if mode not in ('legacy','registered-v1'):raise ValueError('unknown native DNS alias mode')
    if mode=='registered-v1':
        if rows or package.get('seed_json','')!='':raise ValueError('registered DNS alias has a conflicting saved definition or seed')
    else:
        expected={'name':table,'type':'host','descr':'DNS Alias: '+name,'address':'da_dnsalias_seed','detail':''}
        if len(rows)!=1 or rows[0]!=expected:raise ValueError('native DNS alias was edited outside this package')
        candidate['aliases']['alias']=[a for a in aliases if a is not rows[0]]
    package['policy_json']=json.dumps([p for p in policies if p['name']!=name],separators=(',',':'))
    references=copy.deepcopy(candidate)
    # Native revision descriptions name the alias that was just saved. They
    # are audit metadata, never a consumer or executable package setting.
    references.pop('revision',None)
    refs=review((table,),configuration=references,filter_rules=filter_rules,nat_rules=nat_rules)
    if refs['has_mentions']:raise ValueError('Alias is still used: '+', '.join(f['path'] for f in refs['findings'][:6]))
    if remove and p['enabled'] and not stopped:raise ValueError('disable and drain this alias before deletion')
    return candidate,table


def plan_seed(configuration,filter_rules,nat_rules):
    """Remove only an owned, unused empty definition after all policies leave."""
    candidate=copy.deepcopy(configuration);table='da_dnsalias_seed'
    package=candidate.get('installedpackages',{}).get('dnsalias',{})
    if json.loads(package.get('policy_json','[]'))!=[]:raise ValueError('delete saved DNS aliases before seed cleanup')
    rows=candidate.get('aliases',{}).get('alias',[])
    if type(rows) is not list:raise ValueError('native alias list required')
    matches=[a for a in rows if str(a.get('name','')).lower()==table]
    raw=package.get('seed_json','')
    if raw=='' and not matches:return None,table
    expected={'name':table,'type':'host','descr':'DNS Alias internal empty definition; never populate','address':'','detail':''}
    if raw=='':raise ValueError('seed has no ownership record; no adoption or removal')
    if type(raw) is not str or len(raw)>4096 or json.loads(raw)!={'format':'dnsalias-native-seed-1','alias':expected}:
        raise ValueError('seed ownership record changed')
    if len(matches)!=1 or matches[0]!=expected:raise ValueError('owned seed definition changed')
    rows=[a for a in rows if a is not matches[0]]
    if rows:candidate['aliases']['alias']=rows
    else:
        del candidate['aliases']['alias']
        if not candidate['aliases']:del candidate['aliases']
    del package['seed_json']
    references=copy.deepcopy(candidate);references.pop('revision',None)
    refs=review((table,),configuration=references,filter_rules=filter_rules,nat_rules=nat_rules)
    if refs['has_mentions']:raise ValueError('Seed is still used: '+', '.join(f['path'] for f in refs['findings'][:6]))
    return candidate,table


def plan_all_stopped(configuration,filter_rules,nat_rules):
    """Plan all unused owned aliases plus seed, preserving ordinary rules."""
    candidate=copy.deepcopy(configuration);package=candidate.get('installedpackages',{}).get('dnsalias',{})
    policies=json.loads(package.get('policy_json','[]'))
    if type(policies) is not list or len(policies)>127 or any(type(p) is not dict for p in policies):raise ValueError('bounded saved policies required')
    names=[p.get('name') for p in policies]
    if any(type(n) is not str for n in names) or len(set(names))!=len(names):raise ValueError('distinct saved policy names required')
    tables=[]
    for name in names:
        candidate,table=plan(name,candidate,filter_rules,nat_rules,remove=True,stopped=True);tables.append(table)
    without_seed,seed=plan_seed(candidate,filter_rules,nat_rules)
    if without_seed is not None:candidate=without_seed;tables.append(seed)
    return candidate,tuple(tables)


@guarded()
def operate(name=None,*,remove=False,seed=False,stopped=False,all_stopped=False,expected_tables=None,root=None,data=None,config=None,locks=None):
    import manage
    from .aliasservice import ROOT, DATA, CONFIG
    root=Path(root or ROOT);data=Path(data or DATA);config=Path(config or CONFIG);locks=Path(locks or '/tmp')
    if not sys.platform.startswith('freebsd') or root!=Path(__file__).resolve().parents[1]:raise ValueError('installed native local transaction required')
    if type(all_stopped) is not bool or all_stopped and (not stopped or not remove or seed or name is not None or type(expected_tables) is not tuple):
        raise ValueError('explicit reviewed stopped batch required')
    if not all_stopped and expected_tables is not None:raise ValueError('reviewed tables belong only to stopped batch removal')
    if type(stopped) is not bool or stopped and (not remove or seed or name is None and not all_stopped):raise ValueError('explicit stopped alias removal required')
    if stopped:
        held=current(root,data)
        if held is None or held.mode!='write':raise ValueError('exclusive source lifetime required for stopped alias removal')
        if any((data/n).exists() or (data/n).is_symlink() for n in ('collector.pid','alias-service.pid','trial-launch.json',
            'trial-prepare-request','observation-prepare-request','hook-trial','alias-registration')):
            raise ValueError('stop owners and retire alias/hook operations before stopped alias removal')
    if type(seed) is not bool or (seed and name is not None):raise ValueError('explicit separate seed operation required')
    if seed and (data/'alias-service.pid').exists():raise ValueError('stop and verify alias service before seed cleanup')
    manifest=manage.verify(root,data);ready(data);uid=os.geteuid();gid=os.getegid();owners=tuple(dict.fromkeys((0,uid)))
    parser=Path('/etc/inc/xmlparse.inc');pi=parser.stat()
    spec=SourceSpec('firewall_config',str(config),uid,gid,(0o600,),2*1024*1024)
    with ExitStack() as stack:
        sources=stack.enter_context(SourceAudit([
            SourceSpec('config_codec',str(root/'native/configcodec.php'),uid,gid,(0o600,),65536),
            SourceSpec('native_xml_parser',str(parser),pi.st_uid,pi.st_gid,(stat.S_IMODE(pi.st_mode),),100000)],ancestor_uids=owners))
        codec=NativeConfigCodec(sources,helper_sha256=manifest['files']['native/configcodec.php']);stack.callback(codec.close)
        pf=stack.enter_context(SourceAudit([SourceSpec('pfctl_binary','/sbin/pfctl',0,0,(0o555,),2*1024*1024)],ancestor_uids=(0,)))
        reload=SharedReloadLock(locks/'filter.lock',expected_uid=uid);guard=ExclusiveConfigLock(locks/'config.lock',expected_uid=uid)
        stack.callback(reload.close);stack.callback(guard.close);stack.enter_context(reload);stack.enter_context(guard)
        audit=stack.enter_context(SourceAudit([spec],ancestor_uids=owners))
        before=_read(audit,audit.files[0],time.monotonic()+1)
        configuration=codec.decode(before)['configuration']
        capture=PFReferenceCapture(pf,reload,guard);capture.capture();refs=capture.arguments()
        if all_stopped:
            candidate,tables=plan_all_stopped(configuration,refs['filter_rules'],refs['nat_rules'])
            if tables!=expected_tables:raise ValueError('saved aliases changed after uninstall review')
            if not tables:return {'aliases_absent':True,'configuration_changed':False,'reference_capture':capture.summary()}
            table=None
        else:
            if seed:candidate,table=plan_seed(configuration,refs['filter_rules'],refs['nat_rules'])
            else:candidate,table=plan(name,configuration,refs['filter_rules'],refs['nat_rules'],remove=remove,stopped=stopped)
            tables=(table,)
        if candidate is None:return {'seed_absent':True,'configuration_changed':False,'reference_capture':capture.summary()}
        if not remove:return {'unused':True,'table':table,'reference_capture':capture.summary()}
        with NativePFTables('',tables) as native:
            for selected in tables:
                try:members=native.read(selected)
                except OSError as e:
                    # FreeBSD's table address query reports ESRCH for an
                    # absent table. Accept either absence code only when the
                    # held, freshly validated PF inventory also excludes it.
                    if e.errno not in (errno.ENOENT,errno.ESRCH) or selected in capture.arguments()['existing_tables']:raise
                    members=set()
                if members:raise ValueError('alias is not empty yet; inspect its service state')
        rendered=codec.encode(candidate);raw=rendered['xml'].encode() if isinstance(rendered['xml'],str) else rendered['xml']
        cache=NativeConfigCache(locks/'config.cache',expected_uid=uid,expected_gid=gid);stack.callback(cache.close)
        journal=stack.enter_context(DeleteFile(data,expected_uid=uid))
        old=journal.read()
        if old is not None and old['checkpoint'].get('phase')!='complete':raise ValueError('prior deletion outcome requires inspection')
        value={'format':DeleteFile.PAYLOAD_FORMAT,'operation':'all_unused' if all_stopped else 'seed' if seed else 'alias',
            **({'tables':list(tables)} if all_stopped else {'table':table}),'phase':'prepared','before_sha256':hashlib.sha256(before).hexdigest(),'after_sha256':hashlib.sha256(raw).hexdigest()}
        digest=journal.save(value,expected_digest=old['file_sha256'] if old else None)
        pending=config.with_name('config.xml.dnsalias-delete.pending')
        fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            os.fchmod(fd,0o600)
            view=memoryview(raw)
            while view:
                n=os.write(fd,view)
                if n<=0:raise OSError('short configuration write')
                view=view[n:]
            os.fsync(fd)
        finally:os.close(fd)
        # Never overwrite a configuration or pending operation changed by another writer.
        audit.audit();capture.arguments()
        os.replace(pending,config)
        directory=os.open(config.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        value['phase']='replaced';digest=journal.save(value,expected_digest=digest)
        cache.invalidate()
        with SourceAudit([spec],ancestor_uids=owners) as fresh:
            observed=_read(fresh,fresh.files[0],time.monotonic()+1)
            if hashlib.sha256(observed).hexdigest()!=value['after_sha256'] or codec.decode(observed)['configuration']!=candidate:raise ValueError('deletion readback changed; inspect outcome')
        summary=capture.summary()
        # Keep reloads excluded until the running writer/watch retire this
        # empty identity. Release config first so its PHP reader can see it.
        guard.__exit__()
        until=time.monotonic()+4
        while not stopped and time.monotonic()<until:
            status_path=data/'alias-status.json'
            if not status_path.exists():break
            status=json.loads(status_path.read_text())
            if status.get('state') not in ('starting','running') or table not in status.get('table_counts',{}):break
            time.sleep(.05)
        else:
            if not stopped:raise ValueError('alias deleted; writer retirement pending. Inspect before making another change')
        value['phase']='complete';journal.save(value,expected_digest=digest)
        return {**({'deleted_tables':list(tables)} if all_stopped else {'deleted':table}),
            'rules_changed':False,'filter_reloaded':False,'reference_capture':summary}


def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('review','remove','review-seed','remove-seed'));p.add_argument('name',nargs='?');a=p.parse_args()
    if os.geteuid()!=0:raise ValueError('native root service required')
    import manage
    if current(manage.ROOT,manage.DATA) is None:
        os.execv('/usr/local/bin/python3.11',['/usr/local/bin/python3.11','-B',str(manage.ROOT/'dnsalias/lifecycle.py'),'operator','policydelete',*sys.argv[1:]])
    try:print(json.dumps(operate(a.name,remove=a.action.startswith('remove'),seed=a.action.endswith('-seed'))))
    except Exception as exc:
        print(str(exc)[:500],file=sys.stderr);raise SystemExit(1)


if __name__=='__main__':main()
