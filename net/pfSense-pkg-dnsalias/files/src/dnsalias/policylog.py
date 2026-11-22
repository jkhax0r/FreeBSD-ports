"""Optional pfBlockerNG 3.x log observations, never lease/enforcement inputs.

The inspected installed logger emits unquoted comma-separated records with
yearless local timestamps. Reject ambiguous times and malformed records. Reply
logs may contain one selected answer, incomplete types or inferred NXDOMAIN;
retain their provenance instead of presenting them as complete wire answers.
"""
import datetime
import ipaddress
import math
import re
import time
from .leases import dns_name

MONTHS={m:i+1 for i,m in enumerate(('Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'))}

def log_time(value,now):
    if type(now) not in (int,float) or not math.isfinite(now) or now<0: return None
    match=re.fullmatch(r'([A-Z][a-z]{2}) ([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})',value)
    if not match or match[1] not in MONTHS: return None
    year=datetime.datetime.fromtimestamp(now).year;found=set()
    for y in (year-1,year,year+1):
        for fold in (0,1):
            try:
                date=datetime.datetime(y,MONTHS[match[1]],*(int(v) for v in match.groups()[1:]),fold=fold)
                stamp=date.timestamp()
                if now-86400<=stamp<=now+2 and datetime.datetime.fromtimestamp(stamp).replace(fold=fold)==date:
                    found.add(stamp)
            except (ValueError,OverflowError,OSError): pass
    return next(iter(found)) if len(found)==1 else None

def parse_policy_log(line,*,now=None):
    if type(line) is not str or len(line)>4096: return None
    parts=line.rstrip('\r\n').split(',')
    if len(parts)!=10 or any(any(ord(c)<32 or ord(c)==127 for c in part) for part in parts): return None
    if parts[0] not in ('DNS-reply','DNSBL-python'): return None
    now=time.time() if now is None else now
    stamp=log_time(parts[1],now)
    if stamp is None: return None
    try:
        reply=parts[0]=='DNS-reply'
        name=dns_name(parts[6] if reply else parts[2])
        client_text=parts[7] if reply else parts[3]
        if '%' in client_text: return None
        client=str(ipaddress.ip_address(client_text))
        if ipaddress.ip_address(client).is_unspecified or ipaddress.ip_address(client).is_multicast: return None
        event={'kind':'dns_reply_log' if reply else 'dns_policy_log','time':stamp,'client':client,'name':name,
               'source':'pfblockerng_reply_log' if reply else 'pfblockerng_dnsbl_log',
               'time_basis':'year_inferred_router_local_time','lease_eligible':False,
               'dns_policy_action':'unknown' if reply else 'block'}
        event['client_basis']='loopback_or_unknown_fallback' if client=='127.0.0.1' else 'logged_source_address'
        if reply:
            if parts[2] not in ('reply','cache','local','resolver') or not re.fullmatch('[A-Za-z0-9]{1,16}',parts[3]): return None
            if len(parts[8])>256 or len(parts[4])>16 or len(parts[5])>16: return None
            answer=parts[8];address=None
            try: address=ipaddress.ip_address(answer)
            except ValueError: pass
            event.update(callback=parts[2],qtype=parts[3],reported_answer_type=parts[4],
                logged_answer=str(address) if address else answer,
                answer_kind='sinkhole' if address is not None and address.is_unspecified else 'address' if address else 'reported_text',
                reported_ttl=parts[5],reported_country=parts[9] if re.fullmatch('[A-Za-z.]{2,4}',parts[9]) else 'unk',
                result='Logged sinkhole' if address is not None and address.is_unspecified else 'Logged reply',
                coverage='Selected logged answer only; not a complete reply or verified rcode')
            if address is None and {parts[3].upper(),parts[4].upper()} & {'HTTPS','SVCB','TYPE64','TYPE65','64','65'}:
                # This vendor log has already destroyed binary bytes. Do not
                # decode its printable fragments as service parameters/IPs.
                event.update(answer_kind='service_parameters_unavailable',
                             logged_answer='Service parameters unavailable in text log')
        else:
            if parts[9] not in ('+','-') or any(len(p)>256 for p in parts[4:9]): return None
            event.update(result='DNSBL block recorded',policy_type=parts[4],block_type=parts[5],
                         policy_group=parts[6],matched_name=parts[7],policy_feed=parts[8])
        return event
    except ValueError: return None
