"""Explicit data-only restore into an empty, disabled owned installation.

No source, hook/ownership receipt, rule, live IP or lease is imported. Native
publication uses the installed codec and existing config/filter guards. A
partial operation is recorded for inspection, never automatically replayed.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from .aliasrefs import review
from .checkpointfile import CheckpointFile
from .lifecycle import guarded
from . import preferences


class ImportFile(CheckpointFile):
    NAME='preferences-import.json';PENDING='preferences-import.pending';LOCK='preferences-import.lock'
    ENVELOPE_FORMAT='dnsalias-preferences-import-envelope-1';PAYLOAD_FORMAT='dnsalias-preferences-import-1'


def annotation_failure(process):
    """Classify bounded child diagnostics without copying backup contents."""
    text=process.stderr.lower()
    if len(getattr(process,'stdout',''))>4096:reason='annotation_result_oversized'
    elif 'database or disk is full'in text:reason='annotation_store_full'
    elif 'allowed memory size'in text or 'out of memory'in text or 'cannot allocate memory'in text:reason='annotation_memory_limit'
    elif process.returncode:reason='annotation_child_failed'
    else:reason='annotation_child_warning'
    return {'reason':reason,'exit_status':process.returncode,'stderr_bytes':len(process.stderr.encode('utf-8')),
        'stderr_sha256':hashlib.sha256(process.stderr.encode('utf-8')).hexdigest()}


def ready(data):
    data=Path(data)
    if os.path.lexists(data/ImportFile.PENDING):raise ValueError('Pending preferences import requires inspection')
    if os.path.lexists(data/ImportFile.NAME):
        with ImportFile(data,expected_uid=os.geteuid())as journal:
            if journal.read()['checkpoint'].get('phase')!='complete':
                raise ValueError('Incomplete preferences import requires inspection; no automatic retry')


def plan(value,configuration,filter_rules,nat_rules,*,occupied_names):
    """Pure plan; preserves unrelated native configuration byte values."""
    value=preferences.validate(value)
    if type(configuration)is not dict:raise ValueError('Fresh native configuration required')
    candidate=copy.deepcopy(configuration);installed=candidate.get('installedpackages')
    package=installed.get('dnsalias')if type(installed)is dict else None
    if type(package)is not dict or package.get('native_alias_mode')!='registered-v1' or package.get('seed_json','')!='':
        raise ValueError('Fresh owned registered alias setup required; no legacy/foreign ownership adoption')
    settings=package.get('config')
    if type(settings)is not list or len(settings)!=1 or type(settings[0])is not dict or settings[0].get('enable')!='off':
        raise ValueError('Disable the global DNS Alias service before importing preferences')
    current=preferences.validate_policies(package.get('policy_json','[]'))
    result=preferences.review_import(value,current_policies=current,service_enabled=False,occupied_names=occupied_names)
    container=candidate.get('aliases',{})
    if container in ('',None):container={}
    if type(container)is not dict:raise ValueError('Fresh native alias container required')
    aliases=container.get('alias',[])
    if aliases in ('',None):aliases=[]
    if type(aliases)is not list or len(aliases)>10000 or any(type(a)is not dict or type(a.get('name'))is not str for a in aliases):
        raise ValueError('Fresh native alias inventory required')
    selected={n.lower()for n in result['tables']}
    if any(a['name'].lower()in selected or a['name'].lower()=='da_dnsalias_seed' for a in aliases):
        raise ValueError('Saved native alias namespace conflicts; no adoption')
    references=copy.deepcopy(configuration);references.pop('revision',None)
    if result['tables']and review(tuple(result['tables']),configuration=references,filter_rules=filter_rules,nat_rules=nat_rules)['has_mentions']:
        raise ValueError('Imported alias name already has consumers; preserve existing decisions')
    package['policy_json']=json.dumps(value['policies'],separators=(',',':'),allow_nan=False)
    return result|{'configuration':candidate,'configuration_changed':candidate!=configuration,'automatic_retry':False}


@guarded(mode='write',control=True)
def operate(value,*,review_only=False,root=None,data=None,config=None,locks=None):
    from .registryentry import inspect as inspect_entry,ROOT,DATA,ENTRY
    from .nativebootstrap import NATIVE_SOURCES
    from .sourceaudit import SourceAudit,SourceSpec
    from .aliascoordinator import _session
    from .hookfile import _read
    root,data=Path(root or ROOT),Path(data or DATA);config,locks=Path(config or '/cf/conf/config.xml'),Path(locks or '/tmp')
    if (not sys.platform.startswith('freebsd')or root!=ROOT or root!=Path(__file__).resolve().parents[1]
        or data!=DATA or config!=Path('/cf/conf/config.xml')or locks!=Path('/tmp')or type(review_only)is not bool):
        raise ValueError('Exact installed native preferences import required')
    value=preferences.validate(value);ready(data)
    pending=config.with_name('config.xml.dnsalias-preferences.pending')
    if os.path.lexists(pending):raise ValueError('Pending preferences configuration publication requires inspection')
    entry=inspect_entry(root,data,ENTRY)
    if not entry['installed']or not entry['matches_source']:raise ValueError('Complete matching owned native registry entry required')
    entry_sha=entry['receipt']['checkpoint']['entry_sha256']
    specs=[SourceSpec('preferences_native_'+str(i),path,0,0,(0o644,),1000000)for i,path in enumerate(NATIVE_SOURCES)]
    with SourceAudit(specs,ancestor_uids=(0,))as native:
        if any(native.hashes[s.name]!=NATIVE_SOURCES[s.path]for s in specs):raise ValueError('Qualified native configuration API changed')
        php="$before=hash_file('sha256','/cf/conf/config.xml');require_once '/etc/inc/config.inc';require_once '/etc/inc/util.inc';$after=hash_file('sha256','/cf/conf/config.xml');if($before!==$after)throw new RuntimeException('Configuration changed during preferences read');echo json_encode(['configuration_sha256'=>$after,'reserved'=>array_keys(get_reserved_table_names())]);"
        p=subprocess.run(['/usr/local/bin/php','-r',php],capture_output=True,text=True,timeout=3)
        if p.returncode or p.stderr or len(p.stdout)>1048576:raise ValueError('Native alias namespace unavailable')
        namespace=json.loads(p.stdout)
        with _session(root=root,data=data,config=config,locks=locks)as session:
            if namespace['configuration_sha256']!=session['before']:raise ValueError('Native namespace changed before import')
            refs=session['references'].arguments()
            proposed=plan(value,session['current'],refs['filter_rules'],refs['nat_rules'],occupied_names=list(namespace['reserved'])+list(refs['existing_tables']))
            if preferences.owned_labels(data):raise ValueError('Import requires empty owned annotations; existing labels are preserved')
            result={k:v for k,v in proposed.items()if k not in ('configuration','policies','labels')}
            if review_only:return result|{'review_only':True,'configuration_changed':False}
            rendered=session['codec'].encode(proposed['configuration']);raw=rendered['xml'].encode()if isinstance(rendered['xml'],str)else rendered['xml']
            with ImportFile(data,expected_uid=os.geteuid())as journal:
                old=journal.read()
                if old is not None and old['checkpoint'].get('phase')!='complete':raise ValueError('Prior preferences import requires inspection')
                checkpoint={'format':ImportFile.PAYLOAD_FORMAT,'phase':'prepared','before_sha256':session['before'],
                    'after_sha256':hashlib.sha256(raw).hexdigest()if proposed['configuration_changed']else session['before'],
                    'bundle_sha256':hashlib.sha256(preferences.dumps(value['policies'],value['labels'])).hexdigest(),
                    'entry_sha256':entry_sha,'policy_count':result['policy_count'],'label_count':result['label_count']}
                digest=journal.save(checkpoint,expected_digest=old['file_sha256']if old else None)
                if value['labels']:
                    program="require "+json.dumps(str(root/'web/preferences.php'))+";$labels=json_decode(stream_get_contents(STDIN,16777217),true,16,JSON_THROW_ON_ERROR);echo json_encode(da_preferences_import_labels('/var/db/dnsalias',$labels),JSON_THROW_ON_ERROR);"
                    p=subprocess.run(['/usr/local/bin/php','-d','memory_limit=128M','-d','display_errors=stderr','-d','log_errors=0','-r',program],
                        input=json.dumps(value['labels']),text=True,capture_output=True,timeout=10)
                    if p.returncode or p.stderr or len(p.stdout)>4096:
                        failure=annotation_failure(p);checkpoint.update(phase='labels_not_confirmed',annotation_failure=failure)
                        journal.save(checkpoint,expected_digest=digest)
                        reason={'annotation_store_full':'Annotation database capacity exceeded',
                            'annotation_memory_limit':'Annotation import memory limit exceeded'}.get(failure['reason'],'Annotation import was not confirmed')
                        raise ValueError(reason+'; inspect preferences-import.json before retrying. No alias configuration was published')
                    if json.loads(p.stdout).get('imported')!=len(value['labels']):raise ValueError('Annotation import count differs; inspect outcome')
                if preferences.owned_labels(data)!=sorted(value['labels'],key=lambda r:r['domain']):raise ValueError('Imported annotations differ; inspect outcome')
                checkpoint['phase']='labels_saved';digest=journal.save(checkpoint,expected_digest=digest)
                if proposed['configuration_changed']:
                    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                    try:
                        os.fchmod(fd,0o600);view=memoryview(raw)
                        while view:
                            n=os.write(fd,view)
                            if n<=0:raise OSError('Short preferences configuration publication')
                            view=view[n:]
                        os.fsync(fd)
                    finally:os.close(fd)
                    native.audit();session['audit'].audit();session['references'].arguments()
                    again=inspect_entry(root,data,ENTRY)
                    if not again['installed']or not again['matches_source']or again['receipt']['checkpoint']['entry_sha256']!=entry_sha:
                        raise ValueError('Native registry entry changed before preferences publication')
                    os.replace(pending,config);directory=os.open(config.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:os.fsync(directory)
                    finally:os.close(directory)
                    checkpoint['phase']='replaced';digest=journal.save(checkpoint,expected_digest=digest);session['cache'].invalidate()
                with SourceAudit([session['spec']],ancestor_uids=session['owners'])as fresh:
                    observed=_read(fresh,fresh.files[0],time.monotonic()+1)
                    if hashlib.sha256(observed).hexdigest()!=checkpoint['after_sha256']or session['codec'].decode(observed)['configuration']!=proposed['configuration']:
                        raise ValueError('Imported configuration readback differs; inspect outcome')
                    session['exclusive'].__exit__()
                    p=subprocess.run(['/usr/local/bin/php',str(root/'native/policies.php')],capture_output=True,text=True,timeout=3)
                    if p.returncode or p.stderr or len(p.stdout)>262144:raise ValueError('Native imported-policy readback unavailable; inspect outcome')
                    if json.loads(p.stdout)!={'format':'dnsalias-saved-aliases-1','policies':value['policies']}:raise ValueError('Imported native policy snapshot differs; inspect outcome')
                    fresh.audit();native.audit()
                checkpoint['phase']='complete';journal.save(checkpoint,expected_digest=digest)
                return result|{'write_authorized':True,'complete':True,'global_service_enabled':False,'dns_changed':False,'pf_changed':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description='Import data-only DNS Alias preferences into an empty disabled owned setup. No service start, rules, leases or ownership import.')
    parser.add_argument('action',choices=('review','import'));parser.add_argument('source',help='Explicit preferences JSON file, or - for stdin')
    args=parser.parse_args(argv)
    try:
        if args.source=='-':raw=sys.stdin.buffer.read(preferences.MAX_BYTES+1)
        else:
            with open(args.source,'rb')as stream:raw=stream.read(preferences.MAX_BYTES+1)
        print(json.dumps(operate(preferences.loads(raw),review_only=args.action=='review')))
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError)as error:
        print('Preferences import not confirmed complete: '+str(error)[:400],file=sys.stderr);return 1
    return 0


def cli():
    # The supported module command re-executes through the existing source
    # lifetime entry before loading its command implementation for mutation.
    # A package update can replace files before operate's decorator runs;
    # re-exec discards any modules imported during that initial window.
    if any(arg in ('-h','--help')for arg in sys.argv[1:]):return main()
    root=Path(__file__).resolve().parents[1];data=Path('/var/db/dnsalias')
    if not sys.platform.startswith('freebsd')or root!=Path('/usr/local/libexec/dnsalias'):
        print('Preferences import requires the installed native FreeBSD package',file=sys.stderr);return 1
    from .lifecycle import current
    if current(root,data)is None:
        os.execve(sys.executable,[sys.executable,'-B',str(root/'dnsalias/lifecycle.py'),'operator','preferenceimport',*sys.argv[1:]],os.environ.copy())
    return main()


if __name__=='__main__':raise SystemExit(cli())
