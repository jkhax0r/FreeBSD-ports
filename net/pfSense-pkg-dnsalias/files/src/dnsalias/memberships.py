"""Inactive pure short-lived projection of independent leases into PF file text.

No files, PF operations, callbacks or locks. Caller must own the ledger while
capturing and authenticate persisted bytes before selection, independently
qualify boot/profile/generation, hold native reload coordination and revalidate
before actual PF load/acknowledgement. Selection is not enforcement approval.
These projections omit name-answer proofs and must NEVER restore a lease engine.
"""
import ipaddress
import json
import math
import re
import socket

from .checkpoint import identity,policy_identity,elapsed_checked
from .leases import LeaseEngine,Policy
from .proofs import ProofLedger
from .replygate import clock


MAX_MEMBERS=20000
MAX_BYTES=4*1024*1024
MAX_AGE=5.0
FIELDS={'format','boot_id','profile_id','policy_id','generation','written_monotonic','written_utc','tables'}


def _generation(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{32}',value):
        raise ValueError('independently qualified generation required')
    return value


def _policies(policies):
    if type(policies) not in (tuple,list) or len(policies)>128 or any(not isinstance(p,Policy) for p in policies):
        raise ValueError('explicit bounded policies required')
    if len({p.name for p in policies})!=len(policies):raise ValueError('duplicate policy identity')
    return tuple(policies)


def _remaining(value):
    if type(value) not in (int,float) or not math.isfinite(value) or not 0<value<=604800:
        raise ValueError('bounded positive remaining lease lifetime required')
    return value


def _destination(value):
    if type(value) is not str or not 1<=len(value)<=45 or '%' in value:
        raise ValueError('bounded literal destination address required')
    if ':' not in value:
        # Native strict IPv4 conversion avoids repeatedly constructing Python
        # network objects during a large reload snapshot. No DNS lookup occurs.
        try:packed=socket.inet_pton(socket.AF_INET,value)
        except OSError as exc:raise ValueError('invalid literal IPv4 address') from exc
        if packed==bytes(4) or packed[0]==127 or 224<=packed[0]<=239:
            raise ValueError('sinkhole or non-destination address')
        return socket.inet_ntop(socket.AF_INET,packed),(4,packed)
    # Preserve the existing ledger's canonical IPv6 representation, including
    # embedded IPv4 forms where inet_ntop and ipaddress use different text.
    address=ipaddress.IPv6Address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError('sinkhole or non-destination address')
    return str(address),(6,address.packed)


def _bounded(value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    if len(raw)>MAX_BYTES:raise ValueError('membership projection exceeds size cap')
    return value


def capture(ledger,*,boot_id,profile_id,generation,now,utc_now):
    """Project current independent leases without mutating or extending them.

    One address remains until the final valid justification in THAT policy.
    Either clock's earlier expiry is conservative. Calling this again never
    assigns a new DNS TTL; remaining validity always comes from original leases.
    Caller supplies qualified metadata; this function cannot establish its trust.
    """
    if not isinstance(ledger,(LeaseEngine,ProofLedger)):raise ValueError('explicit independent lease ledger required')
    identity(boot_id);identity(profile_id);_generation(generation);clock(now);clock(utc_now)
    policies=_policies(ledger.policies);tables={p.name:{} for p in policies};members=0
    if len(ledger.leases)>100000:raise ValueError('lease input cap exceeded')
    for lease in ledger.leases.values():
        if lease.policy not in tables:raise ValueError('lease refers to an unknown policy')
        clock(lease.deadline);clock(lease.expires_utc)
        remaining=min(lease.deadline-now,lease.expires_utc-utc_now)
        if remaining<=0:continue
        _remaining(remaining);address,_=_destination(lease.address)
        current=tables[lease.policy]
        if address not in current:
            members+=1
            if members>MAX_MEMBERS:raise ValueError('membership capacity exceeded')
        current[address]=max(current.get(address,0),remaining)
    return _bounded({'format':'dnsalias-memberships-1','boot_id':boot_id,'profile_id':profile_id,
        'policy_id':policy_identity(policies),'generation':generation,
        'written_monotonic':now,'written_utc':utc_now,
        'tables':{p:dict(sorted(rows.items())) for p,rows in sorted(tables.items())}})


def select(snapshot,policies,*,boot_id,profile_id,generation,now,utc_now):
    """Validate an authenticated projection and produce canonical local PF files.

    Age>=5s, changed identities/policies/generation or clock discontinuity fail.
    Expired members disappear independently. valid_until_monotonic is the first
    selected expiry or projection freshness deadline, whichever is earlier.
    A caller must discard/recompute if loading is delayed beyond that deadline;
    no directory, lock, watchdog or actual load is supplied here.
    """
    policies=_policies(policies);identity(boot_id);identity(profile_id);_generation(generation)
    clock(now);clock(utc_now)
    if type(snapshot) is not dict or set(snapshot)!=FIELDS or snapshot['format']!='dnsalias-memberships-1':
        raise ValueError('complete membership projection required')
    if (snapshot['boot_id']!=boot_id or snapshot['profile_id']!=profile_id or snapshot['generation']!=generation
        or snapshot['policy_id']!=policy_identity(policies)):
        raise ValueError('membership identity changed; fresh capture required')
    age=elapsed_checked((snapshot['written_monotonic'],snapshot['written_utc']),(now,utc_now),.25)
    if age>=MAX_AGE:raise ValueError('membership projection stale')
    tables=snapshot['tables']
    if type(tables) is not dict or set(tables)!={p.name for p in policies}:raise ValueError('policy tables mismatch')
    output={};count=0;until=now+MAX_AGE-age
    for policy,rows in sorted(tables.items()):
        if type(rows) is not dict or len(rows)>MAX_MEMBERS:raise ValueError('bounded address map required')
        addresses=[]
        for raw,remaining in rows.items():
            count+=1
            if count>MAX_MEMBERS:raise ValueError('membership capacity exceeded')
            address,key=_destination(raw)
            if address!=raw:raise ValueError('canonical destination IP required')
            left=_remaining(remaining)-age
            if left>0:
                addresses.append((key,address));until=min(until,now+left)
        # Stable numeric order across both address families; only canonical IPs
        # and newlines reach a future file writer. No names, subnets or PF syntax.
        addresses.sort()
        output['da_'+policy]=''.join(a+'\n' for _,a in addresses)
    _bounded(snapshot)
    return {'format':'dnsalias-selected-memberships-1','files':output,
        'selected_monotonic':now,'valid_until_monotonic':until,
        'enforcement_applied':False,'qualification':'selection_only; owned publication and reload coordination required'}
