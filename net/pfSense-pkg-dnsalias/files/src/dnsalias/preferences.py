"""Data-only preference backups and import review; no import publisher yet.

Bundles contain saved names and review/tag data, never executable code, DNS
hooks, source paths, ownership receipts, firewall rules, live IPs or leases.
Validation and review perform no writes. A future native import coordinator
must independently qualify the fresh destination and publish each data area.
"""
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import re
import sqlite3
from .ipc import strict_pairs,invalid_number
from .registrymigration import policies as validate_policies

FORMAT='dnsalias-preferences-1'
MAX_BYTES=16*1024*1024
MAX_LABELS=20000
MAX_XML_BYTES=2*1024*1024
MAX_XML_ELEMENTS=20000
MAX_XML_DEPTH=32


def _label(row):
    if type(row) is not dict or set(row)!={'domain','review','tags'}:
        raise ValueError('Data-only domain review and tags required')
    domain,review,tags=row['domain'],row['review'],row['tags']
    if (type(domain) is not str or not 1<=len(domain)<=253
        or not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_.-]*[a-z0-9_])?',domain)
        or any(not 1<=len(label)<=63 for label in domain.split('.'))):
        raise ValueError('Canonical exact domain label required')
    if type(review) is not str or review not in ('','good','bad','investigate'):
        raise ValueError('Known domain review required')
    if (type(tags) is not list or len(tags)>8 or any(type(t) is not str
        or not re.fullmatch(r'[a-z0-9][a-z0-9 _./-]{0,39}',t) or t!=t.strip() for t in tags)
        or tags!=sorted(set(tags))):
        raise ValueError('Canonical bounded unique domain tags required')
    if not review and not tags:raise ValueError('Empty annotation should not be saved')
    return row


def validate(value):
    if type(value) is not dict or set(value)!={'format','policies','labels'} or value['format']!=FORMAT:
        raise ValueError('Data-only DNS Alias preference backup required; no ownership or code fields')
    saved=validate_policies(json.dumps(value['policies'],separators=(',',':'),allow_nan=False))
    labels=value['labels']
    if type(labels) is not list or len(labels)>MAX_LABELS:raise ValueError('Bounded domain annotations required')
    seen=set()
    for row in labels:
        _label(row)
        if row['domain'] in seen:raise ValueError('Duplicate domain annotation')
        seen.add(row['domain'])
    return {'format':FORMAT,'policies':copy.deepcopy(saved),'labels':copy.deepcopy(labels)}


def loads(raw):
    if type(raw) not in (bytes,str):raise ValueError('Preference JSON bytes required')
    if not 0<len(raw)<=MAX_BYTES or type(raw) is str and len(raw.encode('utf-8'))>MAX_BYTES:
        raise ValueError('Bounded preference backup required')
    return validate(json.loads(raw,object_pairs_hook=strict_pairs,parse_constant=invalid_number))


def dumps(policies,labels):
    value=validate({'format':FORMAT,'policies':policies,'labels':labels})
    value['labels'].sort(key=lambda row:row['domain'])
    raw=(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode()
    if len(raw)>MAX_BYTES:raise ValueError('Preference backup size limit')
    return raw


def owned_labels(data):
    """Read verified owned annotations; never copy their SQLite/owner files."""
    from . import domainlabels
    data=Path(data);path=domainlabels.store_path(data)
    if not os.path.lexists(path):return []
    def read():
        before=domainlabels._inspect(data,path)
        labels=[];current=None
        with closing(sqlite3.connect((path/'labels.sqlite').as_uri()+'?mode=ro',uri=True,timeout=.25)) as db:
            db.execute('BEGIN')
            if db.execute('PRAGMA foreign_key_check').fetchone() is not None:raise ValueError('Annotation relation changed')
            for domain,review,tag in db.execute('SELECT l.domain,l.review,t.tag FROM domain_labels l LEFT JOIN domain_tags t ON t.domain=l.domain ORDER BY l.domain,t.tag'):
                if current is None or current['domain']!=domain:
                    if current is not None:_label(current)
                    if len(labels)>=MAX_LABELS:raise ValueError('Annotation capacity exceeded')
                    current={'domain':domain,'review':review,'tags':[]};labels.append(current)
                if tag is not None:
                    if len(current['tags'])>=8:raise ValueError('Annotation tag capacity exceeded')
                    current['tags'].append(tag)
            if current is not None:_label(current)
            db.rollback()
        if domainlabels._inspect(data,path)!=before:raise ValueError('Annotations changed during export')
        return labels
    return domainlabels._locked(data,path,read)


def review_import(value,*,current_policies,service_enabled,occupied_names):
    """Pure fresh-destination plan; this is never write authorization."""
    value=validate(value)
    if current_policies!=[] or type(current_policies) is not list or service_enabled is not False:
        raise ValueError('Fresh empty aliases and globally disabled service required for import')
    if (type(occupied_names) not in (tuple,list) or len(occupied_names)>10000
        or any(type(n) is not str or len(n)>255 for n in occupied_names)):
        raise ValueError('Bounded fresh native namespace required')
    occupied={name.lower() for name in occupied_names}
    tables=['da_'+p['name'] for p in value['policies']]
    if any(name in occupied for name in tables):raise ValueError('Imported table conflicts with native namespace; no adoption')
    return {'format':'dnsalias-preferences-import-review-1','policies':value['policies'],'labels':value['labels'],
        'tables':tables,'policy_count':len(value['policies']),'label_count':len(value['labels']),
        'tag_assignments':sum(len(row['tags']) for row in value['labels']),
        'source_or_ownership_imported':False,'rules_created':False,'service_started':False,'write_authorized':False}


def from_pfsense_xml(raw):
    """Extract only saved names from plaintext XML, never restore its metadata.

    This is an offline data conversion, not native configuration publication.
    Domain annotations and statistics are external to the XML and cannot be
    reconstructed here. No DTD/entities, external lookup or unbounded tree is
    accepted; unrelated configuration values never enter the result.
    """
    from xml.etree import ElementTree as xml
    if type(raw) not in (bytes,str):raise ValueError('Plaintext pfSense XML bytes required')
    if not 0<len(raw)<=MAX_XML_BYTES:raise ValueError('Bounded plaintext pfSense XML required')
    text=raw.decode('utf-8-sig') if type(raw) is bytes else raw
    if len(text.encode('utf-8'))>MAX_XML_BYTES or '\x00' in text:
        raise ValueError('Bounded UTF-8 pfSense XML required')
    if re.search(r'<\s*!\s*(?:DOCTYPE|ENTITY)\b',text,re.IGNORECASE):
        raise ValueError('XML declarations for DTDs or entities are not supported')
    parser=xml.XMLPullParser(events=('start','end'))
    path=[];elements=0;counts=[0,0,0,0];saved=None
    selected=('pfsense','installedpackages','dnsalias','policy_json')
    try:
        for offset in range(0,len(text),4096):
            parser.feed(text[offset:offset+4096])
            for event,element in parser.read_events():
                if event=='start':
                    path.append(element.tag);elements+=1
                    if len(path)>MAX_XML_DEPTH or elements>MAX_XML_ELEMENTS:
                        raise ValueError('pfSense XML structure exceeds the extraction limit')
                    if len(path)==1 and path[0]!=selected[0]:raise ValueError('Plaintext pfSense configuration root required')
                    if tuple(path)==selected[:len(path)] and len(path)<=len(selected):
                        index=len(path)-1;counts[index]+=1
                        if counts[index]!=1:raise ValueError('Ambiguous duplicate DNS Alias XML container')
                else:
                    if tuple(path)==selected:
                        if len(element) or type(element.text) is not str:
                            raise ValueError('Scalar saved DNS policy JSON required in XML')
                        saved=element.text
                    # Keep only the one selected scalar rather than retaining
                    # all of an appliance's unrelated configuration in memory.
                    element.clear();path.pop()
        parser.close()
    except xml.ParseError as exc:raise ValueError('Valid plaintext pfSense XML required') from exc
    if counts!=[1,1,1,1] or saved is None:raise ValueError('Saved DNS Alias names are absent from this XML backup')
    return validate({'format':FORMAT,'policies':validate_policies(saved),'labels':[]})


def main(argv=None):
    """Explicit offline conversion only; no default live configuration path."""
    import argparse
    import sys
    parser=argparse.ArgumentParser(description='Extract DNS alias names from a plaintext pfSense XML backup. No restore, service or firewall action.')
    parser.add_argument('action',choices=('extract-xml',))
    parser.add_argument('source',help='Explicit plaintext XML backup path, or - for standard input')
    parser.add_argument('--output',help='Create a new UTF-8 data-only preferences file; existing files are never overwritten')
    args=parser.parse_args(argv)
    try:
        if args.source=='-':raw=sys.stdin.buffer.read(MAX_XML_BYTES+1)
        else:
            with open(args.source,'rb') as stream:raw=stream.read(MAX_XML_BYTES+1)
        value=from_pfsense_xml(raw);body=dumps(value['policies'],[])
        if args.output is None:sys.stdout.buffer.write(body)
        else:
            flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
            fd=os.open(args.output,flags,0o600)
            try:
                with os.fdopen(fd,'wb') as stream:
                    stream.write(body);stream.flush();os.fsync(stream.fileno())
            except BaseException:
                # Keep a partially written output for inspection. Never guess
                # that a failed write did not create or publish any bytes.
                raise
            print(json.dumps({'format':FORMAT,'policies':len(value['policies']),
                'labels_in_xml':False,'source_or_ownership_imported':False,'configuration_changed':False}))
    except (OSError,ValueError) as exc:
        print('DNS Alias XML extraction was not confirmed complete: '+str(exc)[:300],file=sys.stderr)
        return 1
    return 0


if __name__=='__main__':raise SystemExit(main())
