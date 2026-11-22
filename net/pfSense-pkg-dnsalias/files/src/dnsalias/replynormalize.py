"""Inactive scalar Unbound 1.26.1 adapter, bound to an explicit profile/epoch.

Authenticate the producer, qualify its actual configuration/script and apply
ReplyGate before calling. A descriptor is not evidence of that qualification.
No sockets, SWIG objects, PF or DNS mutations. Trusted means resolver-observed,
not DNSSEC-secure. Unknown versions require separate qualification.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import ipaddress
import json
import math
import re
from .leases import dns_name,valid_clock


class UnqualifiedReply(ValueError): pass


@dataclass(frozen=True)
class ReplyProfile:
    version: str
    identifier: str
    excluded_addresses: tuple=()

    def __post_init__(self):
        if self.version!='1.26.1' or not isinstance(self.identifier,str) or not re.fullmatch('[a-f0-9]{64}',self.identifier):
            raise UnqualifiedReply('explicit qualified version/profile identity required')
        if not isinstance(self.excluded_addresses,(tuple,list,set,frozenset)) or len(self.excluded_addresses)>16:
            raise UnqualifiedReply('bounded sinkhole configuration required')
        if any(type(a) is not str for a in self.excluded_addresses):
            raise UnqualifiedReply('explicit sinkhole address text required')
        object.__setattr__(self,'excluded_addresses',tuple(sorted({str(ipaddress.ip_address(a)) for a in self.excluded_addresses})))


def cname(raw):
    labels=[];pos=0
    while pos<len(raw):
        size=raw[pos];pos+=1
        if size==0:
            if pos!=len(raw) or not labels: raise UnqualifiedReply('invalid CNAME end')
            return dns_name('.'.join(labels))
        if size>63 or pos+size>len(raw) or len(labels)>126:
            raise UnqualifiedReply('compressed or invalid CNAME')
        label = raw[pos:pos+size]
        if b'.' in label:
            raise UnqualifiedReply('CNAME label cannot be represented as a hostname')
        labels.append(label.decode('ascii'));pos+=size
    raise UnqualifiedReply('unterminated CNAME')


def normalize(event,*,profile,resolver_epoch):
    try: return _normalize(event,profile,resolver_epoch)
    except UnqualifiedReply: raise
    except (ValueError,TypeError,KeyError,OverflowError,UnicodeError) as exc:
        raise UnqualifiedReply('malformed scalar reply') from exc


@lru_cache(maxsize=8192)
def _rdata(kind,encoded):
    """Pure bounded RR decoding. Envelope, exclusions and TTL stay uncached."""
    raw=bytes.fromhex(encoded)
    if kind=='CNAME':return cname(raw)
    if kind not in ('A','AAAA'):raise UnqualifiedReply('unsupported record')
    if len(raw)!=(4 if kind=='A' else 16):raise UnqualifiedReply('address length')
    address=ipaddress.ip_address(raw)
    if address.is_unspecified or address.is_loopback or address.is_multicast:
        raise UnqualifiedReply('sinkhole or inadmissible address in answer')
    return str(address)


@lru_cache(maxsize=8192)
def _rrset_identity(profile,epoch,name,kind,values):
    return hashlib.sha256(json.dumps([profile,epoch,name,kind,values],separators=(',',':')).encode()).hexdigest()


def _template_key(rows):
    """Bound retained input; only exact immutable scalar values may be keys."""
    if len(rows)>64:return None
    key=[]
    for rr in rows:
        if type(rr) is not dict:return None
        name,kind,klass=rr.get('name'),rr.get('type'),rr.get('class')
        encoded,ttl,flags=rr.get('rdata_hex'),rr.get('raw_ttl'),rr.get('rrset_flags')
        if (type(name) is not str or len(name)>254 or type(kind) is not str or kind not in ('A','AAAA','CNAME')
            or type(klass) is not str or klass!='IN' or type(encoded) is not str or len(encoded)>510
            or type(ttl) is not int or not 0<=ttl<2**63 or type(flags) is not int or not 0<=flags<2**32):
            return None
        key.append((name,kind,encoded,ttl,flags))
    return tuple(key)


def _record_template(rows,profile,epoch,cached,basis):
    """Immutable absolute expiries only; never cache remaining TTL or trust."""
    values=[];groups={}
    for rr in rows:
        if type(rr) is not dict:raise UnqualifiedReply('scalar RR required')
        if rr.get('class')!='IN':raise UnqualifiedReply('explicit Internet-class record required')
        kind=rr['type'];name=dns_name(rr['name']);encoded=rr['rdata_hex']
        if type(encoded) is not str or len(encoded)>510 or len(encoded)%2 or not re.fullmatch('[a-fA-F0-9]*',encoded):
            raise UnqualifiedReply('bounded hexadecimal RDATA required')
        value=_rdata(kind,encoded);ttl=rr['raw_ttl'];flags=rr['rrset_flags']
        if type(ttl) is not int or ttl<0:raise UnqualifiedReply('invalid raw TTL')
        # UPSTREAM_0TTL takes precedence over raw/fixed TTLs, including grace.
        if type(flags) is not int or flags<0 or flags&~0x80000060:
            raise UnqualifiedReply('unsupported or missing RRset flags')
        if flags&0x40 and not flags&0x20:raise UnqualifiedReply('grace TTL without upstream zero TTL')
        if cached and flags&0x80000000:raise UnqualifiedReply('fixed TTL in cached answer is unqualified')
        expiry=ttl if cached else basis+ttl
        if flags&0x20:expiry=basis
        values.append((name,kind,value,expiry));groups.setdefault((name,kind),set()).add((value,expiry))
    identities={key:_rrset_identity(profile,epoch,*key,tuple(sorted(items))) for key,items in groups.items()}
    return tuple((*row,identities[row[:2]]) for row in values)


@lru_cache(maxsize=128)
def _cached_record_template(profile,epoch,cached,basis,key):
    rows=({'name':name,'type':kind,'class':'IN','rdata_hex':encoded,'raw_ttl':ttl,'rrset_flags':flags}
          for name,kind,encoded,ttl,flags in key)
    return _record_template(rows,profile,epoch,cached,basis)


def _normalize(event,profile,resolver_epoch):
    if not isinstance(profile,ReplyProfile) or type(event) is not dict:
        raise UnqualifiedReply('profile and scalar reply required')
    if not isinstance(resolver_epoch,str) or not re.fullmatch('[a-f0-9]{32}',resolver_epoch):
        raise UnqualifiedReply('qualified resolver epoch required')
    if event.get('resolver_generation')!=resolver_epoch or event.get('profile_id')!=profile.identifier:
        raise UnqualifiedReply('reply profile or resolver epoch mismatch')
    blocked=event.get('policy_block_registry_match',False)
    if type(blocked) is not bool or blocked:
        raise UnqualifiedReply('existing policy block or unqualified policy metadata')
    if type(event.get('qclass')) is not int or event['qclass']!=1:
        raise UnqualifiedReply('explicit Internet-class query required')
    query=dns_name(event['qname']);now=event['time'];valid_clock(now)
    callback=event['callback']
    if callback=='resolved':
        if event.get('module_finished') is not True or event.get('same_return_reply') is not True or type(event.get('return_rcode')) is not int or event['return_rcode']!=0:
            raise UnqualifiedReply('unfinished, substituted or failed resolution')
        basis=event['resolver_now']
    elif callback in ('cache','local'): basis=event['callback_start_time']
    else: raise UnqualifiedReply('failure or unsupported reply callback')
    valid_clock(basis)
    if basis<0 or not 0<=now-basis<5:
        raise UnqualifiedReply('clock discontinuity or unqualified delay')
    flags=event['reply_flags']
    if type(flags) is not int or not 0<=flags<=65535 or not flags&0x8000:
        raise UnqualifiedReply('invalid or non-response flags')
    if type(event['rcode']) is not int or event['rcode']!=0 or flags&15:
        raise UnqualifiedReply('non-positive reply')
    if type(event['answer_rrsets']) is not int or not 1<=event['answer_rrsets']<=64:
        raise UnqualifiedReply('no qualified answer section; never admit delegation glue')
    if callback=='cache':
        ttl=event['reply_ttl']
        if type(ttl) is not int or not 0<ttl-math.floor(basis)<=604800:
            raise UnqualifiedReply('expired or excessive cached reply')
    rows=event['records']
    if type(rows) is not list or len(rows)>256: raise UnqualifiedReply('record bound')
    cached=callback=='cache';floor=math.floor(basis)
    # Fresh/local answers have relative TTLs and commonly change their absolute
    # expiry on the next query. Avoid retaining those short-lived templates.
    key=_template_key(rows) if cached else None
    if key is not None and type(profile.identifier) is str and type(resolver_epoch) is str:
        # Ordinary cache RR TTLs already are absolute. UPSTREAM_0TTL instead
        # depends on the current callback second, which must remain in the key.
        origin=0 if cached and not any(row[4]&0x20 for row in key) else floor
        template=_cached_record_template(profile.identifier,resolver_epoch,cached,origin,key)
    else:template=_record_template(rows,profile.identifier,resolver_epoch,cached,floor)
    normalized=[];excluded=profile.excluded_addresses
    for name,kind,value,expiry,identity in template:
        if kind in ('A','AAAA') and value in excluded:
            raise UnqualifiedReply('sinkhole or inadmissible address in answer')
        remaining=max(0,expiry-now)
        if remaining>604800: raise UnqualifiedReply('expiry exceeds bound')
        normalized.append({'name':name,'type':kind,'value':value,'remaining_ttl':remaining,'proof_id':identity})
    return {'trusted':True,'ttl_basis':'remaining','stale':False,'qname':query,'rcode':'NOERROR',
            'observed_utc':now,'records':normalized,'qualification':'unbound-1.26.1-profile-bound'}
