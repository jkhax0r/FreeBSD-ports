"""Pure, conservative lease recovery; no disk writes, hooks or PF operations.

The caller must authenticate a root-owned checkpoint and qualify boot/profile
identity. A changed boot or profile requires rebuilding from fresh observations.
Same-boot restart uses elapsed monotonic time, never a new full TTL.
"""
import hashlib
import json
import re

from .proofs import ProofLedger
from .replygate import ReplyGate, clock


class RejectedCheckpoint(ValueError): pass


def identity(value):
    if not isinstance(value,str) or not re.fullmatch('[a-f0-9]{64}',value):
        raise RejectedCheckpoint('qualified identity digest required')
    return value


def policy_identity(policies):
    rows=sorted((p.name,sorted(set(p.patterns))) for p in policies)
    return hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest()


def clock_pair(mono,utc):
    return clock(mono),clock(utc)


def elapsed_checked(previous, current, tolerance):
    earlier_mono,earlier_utc=clock_pair(*previous)
    mono,utc=clock_pair(*current)
    elapsed_mono,elapsed_utc=mono-earlier_mono,utc-earlier_utc
    if elapsed_mono<0 or elapsed_utc<0 or abs(elapsed_utc-elapsed_mono)>tolerance:
        raise RejectedCheckpoint('clock continuity unqualified; rebuild required')
    # Small permitted negative wall-clock drift must never extend a lease.
    return max(elapsed_mono,elapsed_utc)


def capture(ledger,gate,*,boot_id,profile_id,now,utc_now):
    identity(boot_id);identity(profile_id);clock_pair(now,utc_now)
    if gate.clock_blocked or gate.active is None or gate.received is None:
        raise RejectedCheckpoint('qualified active resolver generation required')
    elapsed_checked(gate.received,(now,utc_now),gate.tolerance)
    return {'format':'dnsalias-checkpoint-1','boot_id':boot_id,'profile_id':profile_id,
            'policy_id':policy_identity(ledger.policies),'written_monotonic':now,
            'written_utc':utc_now,'generation':list(gate.active),
            'ledger':ledger.snapshot(now,utc_now)}


def restore(checkpoint,policies,*,boot_id,profile_id,now,utc_now,
            max_proofs=100000,max_leases=100000,max_walk=100000):
    """Return a new ledger/gate pair, or reject without mutating caller state.

    Even a trusted wall clock does not authorize restoration after reboot.
    Existing PF contents are not evidence and are never imported here.
    """
    identity(boot_id);identity(profile_id);clock_pair(now,utc_now)
    policies=tuple(policies)
    if not isinstance(checkpoint,dict) or set(checkpoint)!={'format','boot_id','profile_id','policy_id','written_monotonic','written_utc','generation','ledger'}:
        raise RejectedCheckpoint('invalid checkpoint envelope')
    if checkpoint['format']!='dnsalias-checkpoint-1' or checkpoint['boot_id']!=boot_id:
        raise RejectedCheckpoint('boot changed or checkpoint unqualified; rebuild required')
    if checkpoint['profile_id']!=profile_id or checkpoint['policy_id']!=policy_identity(policies):
        raise RejectedCheckpoint('resolver profile or policies changed; rebuild required')
    gate=ReplyGate()
    elapsed=elapsed_checked((checkpoint['written_monotonic'],checkpoint['written_utc']),(now,utc_now),gate.tolerance)
    generation=checkpoint['generation']
    if not isinstance(generation,list) or len(generation)!=2:
        raise RejectedCheckpoint('invalid saved generation')
    started,token=generation
    clock(started)
    if started>checkpoint['written_monotonic'] or not isinstance(token,str) or not re.fullmatch('[a-f0-9]{32}',token):
        raise RejectedCheckpoint('invalid saved generation')
    saved=checkpoint['ledger']
    if not isinstance(saved,dict) or saved.get('format')!='dnsalias-proofs-1' or saved.get('written_utc')!=checkpoint['written_utc']:
        raise RejectedCheckpoint('inconsistent proof snapshot')
    rows=saved.get('proofs')
    if not isinstance(rows,list) or len(rows)>max_proofs:
        raise RejectedCheckpoint('saved proof capacity exceeded')
    adjusted=[]
    for row in rows:
        if not isinstance(row,dict): raise RejectedCheckpoint('invalid saved proof')
        expiry=clock(row['expires_utc'])
        original_remaining=expiry-checkpoint['written_utc']
        if not 0<=original_remaining<=604800:
            raise RejectedCheckpoint('invalid persisted TTL')
        remaining=max(0,original_remaining-elapsed)
        adjusted.append(row|{'expires_utc':utc_now+remaining})
    ledger=ProofLedger(policies,max_proofs=max_proofs,max_leases=max_leases,max_walk=max_walk)
    ledger.restore(saved|{'written_utc':utc_now,'proofs':adjusted},now,utc_now,trusted_clock=True)
    gate.active=(started,token)
    gate.received=(now,utc_now)
    return ledger,gate
