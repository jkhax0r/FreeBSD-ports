"""Bounded historical DNS candidates, never exact HTTP/HTTPS hostname evidence.

Only the particular client's observed replies justify client attribution. Alias
destination tables may be shared, but another client's lookup is not evidence
of this client's hostname use. Production reply ingestion is not wired here.
"""
from dataclasses import dataclass,replace
import heapq
import ipaddress

from .leases import Policy,valid_clock
from .proofs import ProofLedger


@dataclass(frozen=True)
class Mapping:
    client: str
    name: str
    address: str
    answer_id: str
    first_seen: float
    expires_utc: float

    @property
    def key(self): return self.client,self.name,self.address,self.answer_id


class MappingHistory:
    def __init__(self,*,max_mappings=20000,history_seconds=86400):
        if type(max_mappings) is not int or not 1<=max_mappings<=100000:
            raise ValueError('invalid mapping capacity')
        if type(history_seconds) is not int or not 1<=history_seconds<=86400:
            raise ValueError('invalid historical window')
        self.max_mappings,self.history_seconds=max_mappings,history_seconds
        self.mappings={};self.by_client_address={};self.coverage_floor=None
        self.expiries=[]

    def observe(self,client,event,*,received_utc):
        client=str(ipaddress.ip_address(client))
        valid_clock(received_utc,event['observed_utc'])
        if not 0<=received_utc-event['observed_utc']<=5:
            raise ValueError('unqualified delivery delay')
        # A per-reply graph uses resolver answers associated with this client.
        # Pre-encoding callbacks can include addresses omitted from the wire;
        # neither this graph nor query history proves reception or hostname use.
        # Other clients' canonical refreshes cannot seed this client's history.
        ledger=ProofLedger([Policy('reply',(event['qname'],))],max_proofs=256,max_leases=256,max_walk=2048)
        leases=ledger.observe(event,received_utc,received_utc)
        floor=received_utc-self.history_seconds
        if self.coverage_floor is not None: floor=max(floor,self.coverage_floor)
        # Stage expired heap entries so capacity failure leaves every index and
        # the historical coverage floor unchanged. Unchanged cache hits never
        # scan/copy the full retained history or append another expiry entry.
        expired=set();popped=[]
        while self.expiries and self.expiries[0][0]<=floor:
            stamp,key=heapq.heappop(self.expiries);popped.append((stamp,key))
            current=self.mappings.get(key)
            if current is not None and current.expires_utc==stamp: expired.add(key)
        updates={}
        for lease in leases:
            row=Mapping(client,lease.name,lease.address,lease.answer_id,event['observed_utc'],lease.expires_utc)
            prior=updates.get(row.key) or (self.mappings.get(row.key) if row.key not in expired else None)
            if prior:
                row=replace(row,first_seen=min(row.first_seen,prior.first_seen),expires_utc=min(row.expires_utc,prior.expires_utc))
            updates[row.key]=row
        added=sum(key not in self.mappings or key in expired for key in updates)
        if len(self.mappings)-len(expired)+added>self.max_mappings:
            for entry in popped: heapq.heappush(self.expiries,entry)
            raise OverflowError('mapping history capacity exceeded; caller must report a coverage gap')
        for key in expired:
            row=self.mappings.pop(key)
            group=(row.client,row.address);del self.by_client_address[group][key]
            if not self.by_client_address[group]: del self.by_client_address[group]
        for key,row in updates.items():
            prior=self.mappings.get(key)
            if prior==row: continue
            self.mappings[key]=row
            self.by_client_address.setdefault((row.client,row.address),{})[key]=row
            if prior is None or row.expires_utc!=prior.expires_utc: heapq.heappush(self.expiries,(row.expires_utc,key))
        # Shortened proofs leave stale heap entries. Rebuild only amortized at
        # the capacity threshold, never once per reply or repeated cache hit.
        if len(self.expiries)>max(1024,2*len(self.mappings)):
            self.expiries=[(row.expires_utc,key) for key,row in self.mappings.items()]
            heapq.heapify(self.expiries)
        self.coverage_floor=floor
        return len(leases)

    def candidates(self,client,address,*,at_utc):
        valid_clock(at_utc)
        client,address=str(ipaddress.ip_address(client)),str(ipaddress.ip_address(address))
        if self.coverage_floor is not None and at_utc<self.coverage_floor:
            return {'domain_attribution':'unknown','domain_candidates':[],'attribution_reason':'outside_retained_mapping_window'}
        names=sorted({row.name for row in self.by_client_address.get((client,address),{}).values()
                      if row.first_seen<=at_utc<row.expires_utc})
        return {'domain_attribution':'ambiguous' if len(names)>1 else 'inferred' if names else 'unknown',
                'domain_candidates':names,
                'attribution_reason':'client_dns_mapping_within_ttl' if names else 'no_valid_client_reply_mapping'}

    def annotate_firewall(self,event,*,client=None,client_identity_verified=False):
        """Preserve actual action/tracker; require explicit interface/NAT mapping."""
        if event.get('kind')!='firewall_packet': raise ValueError('firewall packet event required')
        if client_identity_verified is not True:
            result={'domain_attribution':'unknown','domain_candidates':[],'attribution_reason':'client_identity_unqualified'}
        else:
            result=self.candidates(client,event['destination'],at_utc=event['time'])
        return event|result|{'attribution_evidence':'resolver_reply_for_client_not_wire_delivery',
                             'attribution_limit':'DNS candidates are not proof of delivered DNS addresses, HTTP Host, HTTPS hostname or URL; packets are not unique requests.'}
