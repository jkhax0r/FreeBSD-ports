"""Inactive, bounded Unbound 1.26.1 callback-to-scalar adapter.

Reads callback objects synchronously; never retains them or mutates a reply.
The result is raw observation data, not a trusted mapping or a PF update.
Caller must qualify the deployed version/profile, authenticate transport and
run replygate/replynormalize. This standalone source can be embedded in a
single hook without importing a package inside the resolver chroot.
"""
import json
import math
import re

MAX_RAW_REPLY_BYTES=58000  # Reserve bounded transport-envelope/health overhead.


def _integer(value,lower,upper):
    if type(value) is not int or not lower<=value<=upper: raise ValueError('invalid scalar integer')
    return value


def _clock(value):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0: raise ValueError('invalid scalar clock')
    return value


def _text(value,limit):
    if type(value) is not str or not 1<=len(value)<=limit: raise ValueError('invalid scalar text')
    return value


def extract_reply(kind,qinfo,qstate,rep,rcode,*,peer=None,callback_start_time=None,
                  module_id,finished_state,observed_utc,observed_monotonic,
                  resolver_generation,generation_started_monotonic,profile_id,
                  unbound_version,policy_block_registry_match=False,policy_bypass_client=False):
    if unbound_version!='1.26.1': raise ValueError('unqualified Unbound version')
    if type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}',profile_id): raise ValueError('explicit profile required')
    if type(resolver_generation) is not str or not re.fullmatch('[a-f0-9]{32}',resolver_generation): raise ValueError('explicit epoch required')
    if kind not in ('resolved','cache','local','servfail'): raise ValueError('unknown callback')
    if type(policy_block_registry_match) is not bool or type(policy_bypass_client) is not bool:
        raise ValueError('explicit optional policy evidence required')
    _integer(module_id,0,63);_integer(finished_state,0,255)
    utc,mono,started=map(_clock,(observed_utc,observed_monotonic,generation_started_monotonic))
    if started>mono: raise ValueError('generation starts after observation')
    q=qinfo if qinfo is not None else qstate.qinfo
    returned=qstate.return_msg if qstate is not None else None
    event={'callback':kind,'time':utc,'monotonic':mono,'resolver_generation':resolver_generation,
           'generation_started_monotonic':started,'profile_id':profile_id,
           'callback_start_time':_clock(callback_start_time) if callback_start_time is not None else None,
           'policy_block_registry_match':policy_block_registry_match,'policy_bypass_client':policy_bypass_client,
           'qname':_text(q.qname_str,254),'qtype':_integer(q.qtype,0,65535),'qclass':_integer(q.qclass,0,65535),'rcode':_integer(rcode,0,65535),
           'client':_text(peer.addr,45) if peer is not None else None,
           'client_port':_integer(peer.port,0,65535) if peer is not None else None,
           'reply_ttl':_integer(rep.ttl,0,2**63-1) if rep is not None else None,
           'reply_flags':_integer(rep.flags,0,65535) if rep is not None else None,
           'reply_security':_integer(rep.security,0,255) if rep is not None else None,
           'resolver_now':_clock(qstate.env.now) if qstate is not None else None,
           'module_finished':qstate.ext_state[module_id]==finished_state if qstate is not None else None,
           'return_rcode':_integer(qstate.return_rcode,0,65535) if qstate is not None else None,
           'has_return_message':returned is not None if qstate is not None else None,
           'same_return_reply':int(rep.this)==int(returned.rep.this) if rep is not None and returned is not None else None,
           'answer_rrsets':_integer(rep.an_numrrsets,0,64) if rep is not None else 0,
           'authority_rrsets':_integer(rep.ns_numrrsets,0,65535) if rep is not None else 0,
           'additional_rrsets':_integer(rep.ar_numrrsets,0,65535) if rep is not None else 0,
           'records':[],'ttl_basis':'unverified','extractor_version':'unbound-1.26.1-scalars-v1'}
    if rep is not None and event['answer_rrsets']:
        # These SWIG properties construct lightweight wrappers. Borrow each
        # wrapper only for this callback; every record and TTL is read afresh.
        rrsets=rep.rrsets
        for i in range(event['answer_rrsets']):
            rr=rrsets[i];key=rr.rk
            kind=key.type_str
            if kind not in ('A','AAAA','CNAME'): continue
            data=rr.entry.data
            count=_integer(data.count,0,128)
            if len(event['records'])+count>256: raise ValueError('record count bound')
            owner=_text(key.dname_str,254)
            rrclass=_text(key.rrset_class_str,16)
            identity=_integer(rr.id,0,2**64-1)
            flags=_integer(key.flags,0,2**32-1)
            ttl=_integer(data.ttl,0,2**63-1)
            if not count:continue
            records,ttls=data.rr_data,data.rr_ttl
            for j in range(count):
                raw=records[j]
                if not 2<=len(raw)<=257: raise ValueError('RDATA length bound')
                raw=bytes(raw)
                if int.from_bytes(raw[:2],'big')!=len(raw)-2: raise ValueError('RDATA prefix mismatch')
                event['records'].append({'name':owner,'type':kind,'class':rrclass,'rrset_id':identity,'rrset_flags':flags,
                                         'rrset_ttl':ttl,'raw_ttl':_integer(ttls[j],0,2**63-1),
                                         'rdata_hex':raw[2:].hex()})
    # The validated scalar schema is at most8192 header bytes plus4096
    # per record, even with12-byte escaped non-BMP characters and the largest
    # finite integer clocks. Twelve records therefore fit below58000 bytes.
    # Avoid serializing ordinary replies here and again in the transport.
    # Unusual Python subclasses/comparison results use the exact legacy bound.
    small_scalars=(len(event['records'])<=12 and type(event['callback']) is str
        and type(event['module_finished']) in (bool,type(None))
        and all(type(row['type']) is str for row in event['records']))
    if not small_scalars and len(json.dumps(event,separators=(',',':'),allow_nan=False).encode())>MAX_RAW_REPLY_BYTES:
        raise ValueError('raw reply byte bound')
    return event
