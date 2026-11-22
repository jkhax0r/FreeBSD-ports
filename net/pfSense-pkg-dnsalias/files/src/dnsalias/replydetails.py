"""Typed diagnostic answer records, after authenticated reply qualification.

This runs on the statistics thread, never before a DNS ACK. Records describe
the resolver's pre-encoding answer object, not proven client delivery. Only
A/AAAA/CNAME are decoded; arbitrary RDATA, HTTPS/SVCB bytes and glue are never
displayed. This history is not an enforcement or lease-recovery input.
"""
import ipaddress
import json
import re
from .leases import dns_name
from .replynormalize import ReplyProfile,UnqualifiedReply,cname,normalize


def describe(reply,*,profile):
    if not isinstance(profile,ReplyProfile) or type(reply) is not dict or reply.get('profile_id')!=profile.identifier:
        raise ValueError('qualified reply profile required')
    base={'answer_details_version':1,'answer_records':[],'answer_kind':'unavailable',
          'answer_detail_status':'not_available','answer_detail_scope':'Selected A/AAAA/CNAME in resolver answer section; client delivery unverified'}
    flags=reply.get('reply_flags')
    if (type(reply.get('rcode')) is not int or reply['rcode']!=0 or type(flags) is not int
        or not 0<=flags<=65535 or not flags&0x8000 or flags&15 or reply.get('callback')=='servfail'):
        return base|{'answer_detail_status':'error_reply_no_answer_claim'}
    raw=reply.get('records')
    if type(raw) is not list or len(raw)>256:raise ValueError('bounded selected records required')
    if not raw:return base|{'answer_detail_status':'no_supported_records_captured'}
    # Reuse the enforcement normalizer solely to describe qualified RR expiry.
    # It may reject sinkholes, stale cache or unsupported policy metadata. Safe
    # typed values can still be displayed, with expiry explicitly unavailable.
    try:
        normalized=normalize(reply,profile=profile,resolver_epoch=reply['resolver_generation'])
    except UnqualifiedReply:normalized=None
    if normalized is not None:
        # The normalizer has already checked each class, wire value and address
        # exclusion. Reuse its newly allocated rows, not a cached expiry/trust
        # decision. Decode raw bytes only for replies without qualified expiry.
        rows=[{'name':row['name'],'type':row['type'],'value':row['value'],
               'expires_utc':reply['time']+row['remaining_ttl'],'expiry_basis':'qualified_remaining',
               'address_kind':None if row['type']=='CNAME' else 'address'} for row in normalized['records']]
    else:rows=_unqualified_details(raw,profile)
    result=base|{'answer_records':rows,'answer_detail_status':'recorded',
                 'answer_kind':'sinkhole' if any(row['address_kind']=='sinkhole' for row in rows) else 'typed_records'}
    if len(json.dumps(result,separators=(',',':'),allow_nan=False).encode())>60000:
        return base|{'answer_detail_status':'detail_size_limit'}
    return result


def _unqualified_details(raw,profile):
    rows=[]
    for record in raw:
        if type(record) is not dict or record.get('class')!='IN':raise ValueError('typed Internet-class record required')
        kind=record.get('type');encoded=record.get('rdata_hex');owner=dns_name(record['name'])
        if type(encoded) is not str or len(encoded)>510 or len(encoded)%2 or not re.fullmatch('[a-fA-F0-9]*',encoded):
            raise ValueError('bounded record bytes required')
        decoded=bytes.fromhex(encoded)
        if kind=='CNAME':value=cname(decoded);address_kind=None
        elif kind in ('A','AAAA'):
            if len(decoded)!=(4 if kind=='A' else 16):raise ValueError('address family length mismatch')
            address=ipaddress.ip_address(decoded);value=str(address)
            address_kind=('sinkhole' if address.is_unspecified else 'configured_exclusion' if value in profile.excluded_addresses
                          else 'loopback' if address.is_loopback else 'multicast' if address.is_multicast else 'address')
        else:raise ValueError('unsupported record bytes are not display text')
        rows.append({'name':owner,'type':kind,'value':value,'expires_utc':None,
                     'expiry_basis':'unavailable',
                     'address_kind':address_kind})
    return rows
