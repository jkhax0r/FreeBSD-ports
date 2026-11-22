"""Bounded, read-only alias removal review; not removal authorization.

Scan supplied current configuration and complete PF filter/NAT text. A caller
must independently prove capture completeness, freshness, locks, writer
retirement and ownership. No files, commands, rules or raw config values are
returned. Conservative token mentions outside native rule fields also require
review: an empty finding list alone never authorizes deletion.
"""
import re
import io
import hashlib
import json
import copy

MAX_NODES=200000
MAX_TEXT_BYTES=16*1024*1024
MAX_FINDINGS=512
MAX_PATH_BYTES=8*1024*1024


def _tree_digest(tree):
    return hashlib.sha256(json.dumps(tree,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def plan_saved_removal(*,seed_name,definitions,configuration,filter_rules,nat_rules,
                       prior_alias_container,prior_alias_list):
    """Plan narrow removal from a fresh tree, never restore a stale full tree.

    Container flags must come from an independently owned install receipt. This
    helper does not authenticate that receipt or authorize writing: exact bytes
    alone are not ownership. The publisher must establish source identity,
    fresh complete references, retired writers and native locking separately.
    An edited, partial, absent or externally referenced set is never removed.
    Newly added unrelated aliases, rules and container metadata are preserved.
    """
    if (type(prior_alias_container) is not bool or type(prior_alias_list) is not bool
        or (prior_alias_list and not prior_alias_container)):
        raise ValueError('explicit consistent prior native container shape required')
    checked=review_saved_set(seed_name=seed_name,definitions=definitions,configuration=configuration,
        filter_rules=filter_rules,nat_rules=nat_rules)
    if checked['namespace_state']!='exact':raise ValueError('complete exact owned alias set required; no repair')
    if checked['has_external_references']:raise ValueError('referenced aliases must be retained')
    before=_tree_digest(configuration);candidate=copy.deepcopy(configuration)
    container=candidate['aliases'];aliases=container['alias'];names=frozenset(definitions)
    indices=[index for index,value in enumerate(aliases) if value['name'] in names]
    container['alias']=[value for value in aliases if value['name'] not in names]
    if not container['alias'] and not prior_alias_list:del container['alias']
    if not container and not prior_alias_container:del candidate['aliases']
    return {'operation':'remove_exact_unreferenced_saved_aliases','configuration':candidate,
        'before_tree_sha256':before,'after_tree_sha256':_tree_digest(candidate),
        'definition_sha256':checked['definition_sha256'],'removed_names':list(definitions),
        'removed_indices':indices,'source_file_hash':None,'native_write_authorized':False,
        'removal_authorized':False,'traffic_rules_changed':False}


def plan_saved_install(*,seed_name,definitions,configuration,filter_rules,nat_rules):
    """Build an unused-alias addition in memory; never write or activate it.

    Adding a previously missing alias can reactivate a dormant rule, so both
    an absent namespace and no saved/runtime mentions are required. An exact
    preexisting set is not adopted. The full candidate contains private native
    configuration: keep it local and do not log it. Tree hashes identify parsed
    data, not source file bytes; publication still needs a fresh locked read,
    source/file ownership, XML roundtrip validation and a durable rollback plan.
    """
    checked=review_saved_set(seed_name=seed_name,definitions=definitions,configuration=configuration,
        filter_rules=filter_rules,nat_rules=nat_rules)
    if checked['namespace_state']!='absent':raise ValueError('existing or partial alias namespace; no adoption')
    if checked['has_external_references']:raise ValueError('new alias could activate an existing reference')
    before=_tree_digest(configuration);candidate=copy.deepcopy(configuration)
    had_container='aliases' in candidate;had_list='alias' in candidate.get('aliases',{})
    aliases=candidate.setdefault('aliases',{}).setdefault('alias',[])
    # Durable JSON receipts canonicalize map key order. Keep appended native
    # list order independent of the definitions map's insertion order.
    ordered_names=[seed_name,*sorted(name for name in definitions if name!=seed_name)]
    indices=list(range(len(aliases),len(aliases)+len(definitions)))
    fields=('name','type','descr','address','detail')
    aliases.extend([{field:definitions[name][field] for field in fields} for name in ordered_names])
    return {'operation':'append_unused_saved_aliases','configuration':candidate,
        'before_tree_sha256':before,'after_tree_sha256':_tree_digest(candidate),
        'definition_sha256':checked['definition_sha256'],'added_names':ordered_names,
        'added_indices':indices,'prior_alias_container':had_container,'prior_alias_list':had_list,
        'source_file_hash':None,'native_write_authorized':False,'traffic_rules_added':False}


def review_saved_set(*,seed_name,definitions,configuration,filter_rules,nat_rules):
    """Inspect a complete expected saved-alias set without adopting or removing it.

    Only exact complete definitions have their own names/internal seed links
    excluded from reference scanning. Every external mention still requires
    retention/review, including disabled rules and unknown package fields.
    Caller must separately prove ownership, complete fresh captures and stopped
    writers under qualified locks; this pure report never authorizes removal.
    """
    if type(definitions) is not dict or not 2<=len(definitions)<=128:
        raise ValueError('complete bounded saved alias definition set required')
    names=tuple(definitions)
    if (type(seed_name) is not str or seed_name not in definitions or
        any(type(n) is not str or not re.fullmatch(r'da_[a-z][a-z0-9_]{0,22}',n) for n in names)):
        raise ValueError('explicit owned seed and policy identities required')
    for name,value in definitions.items():
        if (type(value) is not dict or set(value)!={'name','type','descr','address','detail'}
            or any(type(v) is not str for v in value.values()) or value['name']!=name
            or value['type']!='host' or value['detail']!=''
            or value['address']!=('' if name==seed_name else seed_name)
            or len(value['descr'].encode('utf-8'))>160 or re.search(r'[\x00-\x1f\x7f]',value['descr'])):
            raise ValueError('exact saved host/empty-seed definition contract required')
    if type(configuration) is not dict or type(configuration.get('aliases',{})) is not dict:
        raise ValueError('explicit native configuration tree required')
    aliases=configuration.get('aliases',{}).get('alias',[])
    if type(aliases) is not list or len(aliases)>10000:
        raise ValueError('bounded ordered native alias inventory required')
    present={};seen=set();changed=[]
    for index,value in enumerate(aliases):
        if (type(value) is not dict or type(value.get('name')) is not str or
            not 1<=len(value['name'])<=128 or re.search(r'[\x00-\x1f\x7f]',value['name'])):
            raise ValueError('explicit valid alias inventory required')
        name=value['name'].lower()
        if name in seen:raise ValueError('ambiguous native alias name collision')
        seen.add(name)
        if name in definitions:
            present[name]=index
            if value!=definitions[name]:changed.append(name)
    missing=[name for name in names if name not in present]
    state='conflict' if changed else ('absent' if not present else ('partial' if missing else 'exact'))
    scanned=configuration
    if state=='exact':
        # Keep original list indices for useful reference paths. Do not mutate
        # the supplied configuration or suppress any unrelated alias fields.
        own_indices=frozenset(present.values())
        scanned=configuration|{'aliases':configuration['aliases']|{'alias':[
            {} if index in own_indices else value for index,value in enumerate(aliases)]}}
    result=review(names,configuration=scanned,filter_rules=filter_rules,nat_rules=nat_rules)
    return {'namespace_state':state,'missing':missing,'changed':changed,
        'definition_sha256':hashlib.sha256(json.dumps(definitions,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        'external_references':result['findings'],'has_external_references':result['has_mentions'],
        'retain_aliases':state!='absent','reference_review_clear':state=='exact' and not result['has_mentions'],
        'removal_authorized':False,'configuration_changed':False,
        'limits':'Exact definitions do not establish ownership. Keep aliases until ownership, complete fresh saved/runtime captures, retired writers and native locking are independently qualified. Partial/changed sets are not repaired or adopted.'}


def review(names,*,configuration,filter_rules,nat_rules):
    if type(names) not in (tuple,list) or not 1<=len(names)<=128:
        raise ValueError('bounded owned alias names required')
    if any(type(n) is not str or not re.fullmatch(r'da_[a-z][a-z0-9_]{0,22}',n) for n in names) or len(set(names))!=len(names):
        raise ValueError('invalid or duplicate owned alias')
    if type(configuration) is not dict or type(filter_rules) is not str or type(nat_rules) is not str:
        raise ValueError('explicit configuration, filter and NAT captures required')
    pattern=re.compile(r'(?<![A-Za-z0-9_])('+ '|'.join(re.escape(n) for n in names) +r')(?![A-Za-z0-9_])',re.IGNORECASE)
    canonical={n.lower():n for n in names};findings=[];seen=set();nodes=0;text_bytes=0;path_bytes=0
    def text(value,source,path,kind):
        nonlocal text_bytes
        text_bytes+=len(value.encode('utf-8'))
        if text_bytes>MAX_TEXT_BYTES:raise OverflowError('reference scan text budget exceeded')
        for match in pattern.finditer(value):
            name=canonical[match.group().lower()];key=(source,path,name,kind)
            if key in seen:continue
            if len(findings)>=MAX_FINDINGS:raise OverflowError('reference scan finding budget exceeded')
            seen.add(key);findings.append({'alias':name,'source':source,'path':path,'evidence':kind})
    stack=[(configuration,'',0)]
    def push(child,path,depth):
        nonlocal path_bytes
        path_bytes+=len(path.encode('utf-8'))
        if path_bytes>MAX_PATH_BYTES:raise OverflowError('reference scan path budget exceeded')
        stack.append((child,path,depth))
    while stack:
        value,path,depth=stack.pop();nodes+=1
        if nodes>MAX_NODES or depth>32:raise OverflowError('reference scan structure budget exceeded')
        if type(value) is dict:
            if nodes+len(stack)+len(value)>MAX_NODES:raise OverflowError('configuration map budget exceeded')
            for key in reversed(value):
                if type(key) is not str or len(key)>160 or re.search(r'[\x00-\x1f\x7f/]',key):
                    raise ValueError('bounded configuration keys required')
                child_path=path+'/'+key
                text(key,'configuration',child_path,'key token mention')
                push(value[key],child_path,depth+1)
        elif type(value) is list:
            if nodes+len(stack)+len(value)>MAX_NODES:raise OverflowError('configuration list budget exceeded')
            for i in range(len(value)-1,-1,-1):push(value[i],path+'/'+str(i),depth+1)
        elif type(value) is str:text(value,'configuration',path,'value token mention')
        elif value is not None and type(value) not in (bool,int,float):raise ValueError('scalar configuration tree required')
    for source,value in (('PF filter rules',filter_rules),('PF NAT rules',nat_rules)):
        # Do not reproduce rule text: it can contain private addresses/labels.
        # Scan bounded lines, including all caller-supplied anchor sections.
        if len(value.encode('utf-8'))+text_bytes>MAX_TEXT_BYTES:raise OverflowError('PF capture text budget exceeded')
        for line,content in enumerate(io.StringIO(value),1):
            if line>MAX_NODES:raise OverflowError('PF capture line budget exceeded')
            text(content,source,'line/'+str(line),'rendered token mention')
    return {'findings':findings,'has_mentions':bool(findings),'nodes_examined':nodes,'text_bytes_examined':text_bytes,
            'removal_authorized':False,
            'limits':'Token mentions are conservative, not a complete native dependency proof. Caller must qualify full saved/runtime captures, freshness, reload locking, retired writer and owned files before removal.'}
