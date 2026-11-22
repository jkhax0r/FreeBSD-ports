"""Compact reply metadata after producer/profile/clock qualification.

DNS rcodes and policy signals are not firewall decisions. In particular,
NXDOMAIN/SERVFAIL are not proof of policy blocking, and a successful resolver
reply is not proof of delivery or HTTP/HTTPS use. This module does not infer
addresses, store raw RRsets, write files, or change DNS/firewall policy.
"""
import ipaddress
import json
import re
from .leases import dns_name, valid_clock

RCODES={0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED',
        6:'YXDOMAIN',7:'YXRRSET',8:'NXRRSET',9:'NOTAUTH',10:'NOTZONE',16:'BADVERS'}
QTYPES={1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',
        43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',50:'NSEC3',64:'SVCB',65:'HTTPS',255:'ANY'}


def summarize(reply, *, client, profile_id):
    """Caller supplies independently authenticated client/profile and fresh clock."""
    if type(reply) is not dict: raise ValueError('scalar reply required')
    if type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}',profile_id) or reply.get('profile_id')!=profile_id:
        raise ValueError('qualified reply profile required')
    epoch=reply.get('resolver_generation')
    if type(epoch) is not str or not re.fullmatch('[a-f0-9]{32}',epoch): raise ValueError('qualified epoch required')
    if type(client) is not str or '%' in client: raise ValueError('canonical client required')
    address=ipaddress.ip_address(client)
    if address.is_unspecified or address.is_multicast: raise ValueError('usable client required')
    client=str(address)
    if str(ipaddress.ip_address(reply.get('client')))!=client: raise ValueError('client mismatch')
    name=reply['qname']
    name='.' if name=='.' else dns_name(name)
    stamp=reply['time'];valid_clock(stamp)
    values=[]
    for key,maximum in (('qtype',65535),('qclass',65535),('rcode',65535),('answer_rrsets',64),('transport_dropped_before',2**63-1)):
        value=reply[key]
        if type(value) is not int or not 0<=value<=maximum: raise ValueError('invalid reply scalar')
        values.append(value)
    qtype,qclass,callback_rcode,answer_rrsets,dropped=values
    callback=reply['callback'];flags=reply.get('reply_flags')
    if callback not in ('resolved','cache','local','servfail'): raise ValueError('known callback required')
    if flags is not None and (type(flags) is not int or not 0<=flags<=65535 or not flags&0x8000):
        raise ValueError('invalid reply header')
    # In pinned Unbound 1.26.1, callback rcode=0 can accompany an NXDOMAIN
    # reply_info header. A nonzero error is instead passed to error_encode,
    # possibly with an earlier answer object still present. Keep both fields.
    if callback_rcode:
        rcode=callback_rcode if callback_rcode<=15 else None
        basis='callback_error' if rcode is not None else 'unqualified_callback_error'
    else:
        rcode=flags&15 if flags is not None else None
        basis='reply_header_low4' if flags is not None else 'missing_reply_header'
    signal='unavailable'
    blocked,bypass=reply.get('policy_block_registry_match'),reply.get('policy_bypass_client')
    if blocked is not None and type(blocked) is not bool or bypass is not None and type(bypass) is not bool:
        raise ValueError('invalid optional policy signal')
    if blocked is True: signal='block_registry_match'
    elif bypass is True: signal='bypass_client'
    elif blocked is False and bypass is False: signal='none_observed'
    event={'kind':'dns_reply','time':stamp,'client':client,'name':name,
           'qtype':QTYPES.get(qtype,'TYPE'+str(qtype)), 'qclass':'IN' if qclass==1 else 'CLASS'+str(qclass),
           'result':RCODES.get(rcode,'RCODE'+str(rcode)) if rcode is not None else 'UNKNOWN', 'rcode':rcode,
           'rcode_basis':basis,'callback_rcode':callback_rcode,'header_rcode':flags&15 if flags is not None else None,
           'extended_rcode_captured':False,
           'source':'unbound_reply_callback','callback':callback,'answer_rrsets':answer_rrsets,
           'truncated_header':bool(flags&512) if flags is not None else None,
           'policy_signal':signal,'dns_policy_action':'unknown','profile_id':profile_id,
           'resolver_generation':epoch,'transport_dropped_before':dropped,
           'evidence':'Resolver callback; client delivery and HTTPS hostname use unverified'}
    if len(json.dumps(event,separators=(',',':'),allow_nan=False).encode())>2048:
        raise ValueError('reply telemetry size bound')
    return event
