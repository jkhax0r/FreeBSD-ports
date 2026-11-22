"""Bounded identity for an optional confirmation of an identical cached reply.

This is not authentication, normalization, or permission to release a reply.
Only the qualified helper may publish after normalizing and synchronizing PF.
The reader still needs current source/generation/lifetime/clock qualification
and a live, unrevoked native receipt. No normal service uses this module yet.
"""
import hashlib
import json
import math
import re
from functools import lru_cache


@lru_cache(maxsize=16384)
def scope_name_keys(name):
    """Pure name hashes, never a cached policy or dependency decision."""
    if type(name) is not str or not 1<=len(name)<=254:
        raise ValueError('bounded DNS name required')
    name=name[:-1] if name.endswith('.') else name
    name=name.lower()
    if len(name)>253 or any(not re.fullmatch('[a-z0-9_-]{1,63}',p) for p in name.split('.')):
        raise ValueError('canonical ASCII DNS name required')
    keys=[hashlib.sha256(('e:'+name).encode('ascii')).digest()]
    # A wildcard does not match its own suffix apex.
    for position,char in enumerate(name):
        if char=='.':keys.append(hashlib.sha256(('s:'+name[position+1:]).encode('ascii')).digest())
    return tuple(keys)


def scope_policy_key(pattern):
    if pattern.startswith('*.'):
        name=pattern[2:]
        scope_name_keys(name)  # Same bounded name validation.
        return hashlib.sha256(('s:'+name.lower().rstrip('.')).encode('ascii')).digest()
    return scope_name_keys(pattern)[0]


def scope_reply_keys(event):
    """Conservative names touched by a complete positive scalar answer.

    Checking only qname is insufficient: any selected RR owner may already
    supply a CNAME-dependent alias. Every observation is still sent to the
    writer, including those that pass this optional no-effect screen.
    """
    if (type(event) is not dict or event.get('callback') not in ('resolved','cache','local')
        or type(event.get('rcode')) is not int or event['rcode']!=0
        or event.get('policy_block_registry_match') is not False):return None
    rows=event.get('records')
    if type(rows) is not list or not 1<=len(rows)<=64:return None
    names={event.get('qname')} if type(event.get('qname')) is str else set()
    if not names:return None
    for row in rows:
        if (type(row) is not dict or type(row.get('name')) is not str
            or row.get('type') not in ('A','AAAA','CNAME') or row.get('class')!='IN'):return None
        names.add(row['name'])
    keys=set()
    try:
        for name in names:
            if len(name)>254:return None  # Keep oversized inputs out of the pure cache.
            keys.update(scope_name_keys(name))
            if len(keys)>512:return None
    except (ValueError,UnicodeError):return None
    return tuple(sorted(keys))

# These observations remain fresh and must still be sent for every query.
# Generation start, policy metadata and every other header field stay bound.
_OBSERVATION=frozenset(('client','client_port','time','monotonic','callback_start_time','request_id'))
_RECORD=frozenset(('name','type','class','rrset_id','rrset_flags','rrset_ttl','raw_ttl','rdata_hex'))


def _clock(value):
    return type(value) in (int,float) and 0<=value<1e15 and math.isfinite(value)


def key_with_loss_counter(event, key):
    """Use the same answer identity across unrelated observation losses."""
    count = event.get('transport_dropped_before')
    if type(count) is not int or not 0 <= count < 2**63:
        return None
    # The authenticated report still carries the real cumulative count.
    return key(event | {'transport_dropped_before': 0}) if count else key(event)


def resolved_cache_key(event, key):
    """Predict the exact cache identity of a finished, ordinary resolution.

    Called only by the writer after authenticating and normalizing the real
    resolved event. The writer still commits that event and its original TTLs.
    The resolver looks up a key from its actual cache reply, so any mismatch
    keeps the normal ACK wait. No prediction is used by the resolver.
    """
    if (event.get('callback')!='resolved' or event.get('module_finished') is not True
        or event.get('has_return_message') is not True or event.get('same_return_reply') is not True
        or type(event.get('return_rcode')) is not int or event['return_rcode']!=0):
        return None
    now,basis=event.get('time'),event.get('resolver_now')
    if not _clock(now) or not _clock(basis) or not 0<=now-basis<5:
        return None
    message_ttl=event.get('reply_ttl')
    rows=event.get('records')
    if (type(message_ttl) is not int or not 1<=message_ttl<=604800
        or type(rows) is not list or not 1<=len(rows)<=64):
        return None
    # Unbound 1.26.1 stores ordinary relative TTLs as integer expiry times.
    # Use the same clock conversion as replynormalize, retaining RRset IDs,
    # record order, RDATA, flags and every other cache identity field.
    origin=math.floor(basis)
    records=[]
    for row in rows:
        if (type(row) is not dict or row.keys()!=_RECORD
            or type(row['rrset_flags']) is not int or row['rrset_flags']!=0
            or any(type(row[name]) is not int or not 1<=row[name]<=604800 for name in ('rrset_ttl','raw_ttl'))):
            return None
        records.append(row | {'rrset_ttl':origin+row['rrset_ttl'],'raw_ttl':origin+row['raw_ttl']})
    cached=event | {'callback':'cache','callback_start_time':basis,'reply_ttl':origin+message_ttl,
                    'resolver_now':None,'module_finished':None,'return_rcode':None,
                    'has_return_message':None,'same_return_reply':None,'records':records}
    return key_with_loss_counter(cached,key)


def confirmation_key(event):
    """Return a 256-bit digest or None; never mutate/cache an observation."""
    if type(event) is not dict or not 1<=len(event)<=64:return None
    if (event.get('extractor_version')!='unbound-1.26.1-scalars-v1'
        or event.get('callback')!='cache' or type(event.get('qtype')) is not int or event['qtype'] not in (1,28)
        or type(event.get('qclass')) is not int or event['qclass']!=1
        or type(event.get('rcode')) is not int or event['rcode']!=0
        or event.get('policy_block_registry_match') is not False
        or type(event.get('policy_bypass_client')) is not bool
        or type(event.get('transport_dropped_before')) is not int or event['transport_dropped_before']!=0):return None
    for field,size in (('profile_id',64),('resolver_generation',32)):
        value=event.get(field)
        if type(value) is not str or not re.fullmatch('[a-f0-9]{'+str(size)+'}',value):return None
    query=event.get('qname')
    if type(query) is not str or not 1<=len(query)<=254:return None
    now,mono,basis,started=(event.get(key) for key in ('time','monotonic','callback_start_time','generation_started_monotonic'))
    if (not all(_clock(v) for v in (now,mono,basis,started)) or started>mono or not 0<=now-basis<5):return None
    flags,count,ttl=(event.get(key) for key in ('reply_flags','answer_rrsets','reply_ttl'))
    if (type(flags) is not int or not 0<=flags<=65535 or not flags&0x8000 or flags&15
        or type(count) is not int or not 1<=count<=64
        or type(ttl) is not int or not 0<=ttl<2**64 or not 0<ttl-now<=604800):return None
    rows=event.get('records')
    if type(rows) is not list or not 1<=len(rows)<=64:return None
    for row in rows:
        if type(row) is not dict or row.keys()!=_RECORD:return None
        if (type(row['name']) is not str or not 1<=len(row['name'])<=254
            or row['type'] not in ('A','AAAA','CNAME') or type(row['type']) is not str or row['class']!='IN'
            or type(row['rrset_flags']) is not int or row['rrset_flags']!=0
            or any(type(row[k]) is not int or not 0<=row[k]<2**64 for k in ('rrset_id','rrset_ttl','raw_ttl'))
            or not 0<row['raw_ttl']-now<=604800
            or type(row['rdata_hex']) is not str or not 1<=len(row['rdata_hex'])<=510):return None
    value={}
    for key,item in event.items():
        if type(key) is not str or len(key)>64:return None
        if key in _OBSERVATION:continue
        if key!='records':
            if type(item) not in (str,int,float,bool,type(None)):return None
            if type(item) is str and len(item)>512:return None
            if type(item) in (int,float) and (abs(item)>=2**64 or not math.isfinite(item)):return None
        value[key]=item
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    return hashlib.sha256(raw).digest() if len(raw)<=16384 else None
