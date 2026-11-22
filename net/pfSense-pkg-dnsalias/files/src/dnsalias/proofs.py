"""Bounded, pure CNAME/address proof ledger for normalized trusted answers.

No Unbound, PF, filesystem or network access. Each record requires a proof_id
stable for its RRset generation across cache hits, distinct on a genuine refresh.
An adapter must establish that contract; raw Unbound identities do not do so.
"""
from dataclasses import dataclass
from functools import lru_cache
import hashlib
import ipaddress
import json

from .leases import Lease, answer_identity, dns_name, valid_clock


@lru_cache(maxsize=16384)
def _lease_identity(keys):
    # Evidence identity is immutable; lease deadlines are always recomputed.
    return hashlib.sha256(json.dumps(keys,separators=(',',':')).encode()).hexdigest()


@lru_cache(maxsize=8192)
def _address_value(kind, value):
    # Only canonical address parsing is reusable. Never cache a proof, its
    # remaining lifetime, query reachability, or policy/trust decision here.
    address = ipaddress.ip_address(value)
    if address.version != (4 if kind == "A" else 6):
        raise ValueError("address family mismatch")
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return None
    return str(address)


@lru_cache(maxsize=8192)
def _record_fields(raw_name, kind, raw_value):
    """Reuse immutable field parsing, never lifetime or answer qualification."""
    name = dns_name(raw_name)
    if kind == "CNAME":
        value = dns_name(raw_value)
    else:
        parse = _address_value if type(kind) is str and type(raw_value) is str and len(raw_value) <= 128 else _address_value.__wrapped__
        value = parse(kind, raw_value)
        if value is None:
            return None
    return name, value


@lru_cache(maxsize=8192)
def _record_identity(value):
    # Each generation is independently validated. Its spelling can be shared
    # across an RRset without tying reusable names/addresses to that generation.
    return answer_identity(value)


@dataclass(frozen=True)
class Proof:
    name: str
    kind: str
    value: str
    identity: str
    deadline: float
    expires_utc: float

    @property
    def key(self):
        return (self.name, self.kind, self.value, self.identity)


class ProofLedger:
    def __init__(self, policies, max_proofs=100000, max_leases=100000, max_walk=100000):
        self.policies = tuple(policies)
        if len(self.policies) > 128 or len({p.name for p in self.policies}) != len(self.policies):
            raise ValueError("duplicate or excessive policies")
        if any(type(x) is not int or not 1 <= x <= 100000 for x in (max_proofs, max_leases, max_walk)):
            raise ValueError("invalid capacity")
        self.max_proofs, self.max_leases, self.max_walk = max_proofs, max_leases, max_walk
        self.proofs, self.anchors, self.leases = {}, set(), {}

    @staticmethod
    def _record(rr, now, utc_now, age):
        kind = rr["type"]
        if kind not in ("A", "AAAA", "CNAME"):
            return None
        raw_name, raw_identity, raw_value = rr["name"], rr["proof_id"], rr["value"]
        # Cache only bounded exact strings. Subclasses and legacy non-string
        # addresses retain the original parser behavior without retention.
        reusable = (type(kind) is str and type(raw_name) is str and len(raw_name) <= 254
                    and type(raw_identity) is str and len(raw_identity) <= 128
                    and type(raw_value) is str and len(raw_value) <= (254 if kind == "CNAME" else 128))
        identity = (_record_identity if type(raw_identity) is str and len(raw_identity) <= 128 else answer_identity)(raw_identity)
        fields = (_record_fields if reusable else _record_fields.__wrapped__)(raw_name, kind, raw_value)
        ttl = rr["remaining_ttl"]
        valid_clock(ttl)
        if not 0 <= ttl <= 604800:
            raise ValueError("invalid normalized TTL")
        ttl = max(0, ttl-age)
        if fields is None:
            return None
        name, value = fields
        return Proof(name, kind, value, identity, now+ttl, utc_now+ttl)

    def _derive(self, proofs, anchors, now):
        by_owner = {}
        for proof in proofs.values():
            if proof.deadline > now:
                by_owner.setdefault(proof.name, []).append(proof)
        return self._walk(by_owner,anchors)

    def _walk(self, by_owner, anchors):
        policies = {p.name:p for p in self.policies}
        anchors = {(policy, name) for policy, name in anchors if by_owner.get(name)
                   and policy in policies and policies[policy].matches(name)}
        if len(anchors) > self.max_leases:
            raise OverflowError("alias root capacity exceeded")
        leases, steps = {}, 0
        for policy, root in sorted(anchors):
            stack = [(root, (), (), float("inf"), float("inf"))]
            while stack:
                owner, path, evidence, deadline, expiry = stack.pop()
                # Retained generations may form a cycle; never derive through it.
                if owner in path or len(path) > 16:
                    continue
                path = path+(owner,)
                for proof in by_owner.get(owner, ()):
                    steps += 1
                    if steps > self.max_walk:
                        raise OverflowError("proof traversal budget exceeded")
                    keys = evidence+(proof.key,)
                    until = min(deadline, proof.deadline)
                    utc_until = min(expiry, proof.expires_utc)
                    if proof.kind == "CNAME":
                        stack.append((proof.value, path, keys, until, utc_until))
                    else:
                        identity = _lease_identity(keys)
                        key = (policy, root, proof.value, identity)
                        leases[key] = Lease(policy, root, proof.value, identity, until, utc_until, path)
                        if len(leases) > self.max_leases:
                            raise OverflowError("derived lease capacity exceeded")
        return anchors, leases

    def _parse_answer(self, event, now, utc_now):
        """Validate a complete answer and select only query-reachable records."""
        valid_clock(now, utc_now)
        if event.get("trusted") is not True or event.get("ttl_basis") != "remaining" or event.get("stale") is not False:
            raise ValueError("verified fresh reply with remaining TTLs required")
        if event.get("rcode") != "NOERROR":
            return None
        query = dns_name(event["qname"])
        valid_clock(event["observed_utc"])
        age = utc_now-event["observed_utc"]
        if not 0 <= age <= 604800:
            raise ValueError("clock ambiguity or excessive delivery delay")
        records = event["records"]
        if not isinstance(records, list) or len(records) > 2048:
            raise ValueError("oversized answer")
        parsed, aliases, address_owners = [], {}, set()
        for rr in records:
            proof = self._record(rr, now, utc_now, age)
            if proof is None:
                continue
            parsed.append(proof)
            if proof.kind == "CNAME":
                if proof.name in aliases and aliases[proof.name] != proof.value:
                    raise ValueError("conflicting CNAME targets within one answer")
                aliases[proof.name] = proof.value
            else:
                address_owners.add(proof.name)
        node, path = query, []
        while node in aliases:
            if node in path or len(path) >= 16 or node in address_owners:
                raise ValueError("invalid CNAME chain")
            path.append(node)
            node = aliases[node]
        if node in path:
            raise ValueError("CNAME loop")
        path.append(node)
        reachable = set(path)
        return query,[proof for proof in parsed if proof.name in reachable]

    def observe(self, event, now, utc_now):
        """Validate, stage and derive before committing any state.

        Only records reachable in this answer from its query are admitted.
        Canonical refreshes can use independently unexpired earlier CNAME edges.
        A query becomes an alias root only when that query matches that policy.
        """
        parsed_answer=self._parse_answer(event,now,utc_now)
        if parsed_answer is None:return []
        query,parsed=parsed_answer
        candidates = {k:v for k,v in self.proofs.items() if v.deadline > now}
        for proof in parsed:
            prior = candidates.get(proof.key)
            if prior and prior.deadline < proof.deadline:
                proof = prior
            candidates[proof.key] = proof
        candidates = {k:v for k,v in candidates.items() if v.deadline > now}
        if len(candidates) > self.max_proofs:
            raise OverflowError("proof capacity exceeded")
        anchors = self.anchors | {(p.name, query) for p in self.policies if p.matches(query)}
        anchors, leases = self._derive(candidates, anchors, now)
        self.proofs, self.anchors, self.leases = candidates, anchors, leases
        return list(leases.values())

    def expire(self, now):
        valid_clock(now)
        proofs = {k:v for k,v in self.proofs.items() if v.deadline > now}
        anchors, leases = self._derive(proofs, self.anchors, now)
        self.proofs, self.anchors, self.leases = proofs, anchors, leases

    def tables(self, now):
        self.expire(now)
        result = {p.name:set() for p in self.policies}
        for lease in self.leases.values():
            result[lease.policy].add(lease.address)
        return result

    def snapshot(self, now, utc_now):
        valid_clock(now, utc_now)
        self.expire(now)
        return {"format":"dnsalias-proofs-1", "written_utc":utc_now,
                "anchors":[list(a) for a in sorted(self.anchors)],
                "proofs":[{"name":p.name,"type":p.kind,"value":p.value,"proof_id":p.identity,
                           "expires_utc":utc_now+p.deadline-now} for p in self.proofs.values()]}

    def restore(self, snapshot, now, utc_now, trusted_clock=False):
        valid_clock(now, utc_now, snapshot["written_utc"])
        if trusted_clock is not True or snapshot.get("format") != "dnsalias-proofs-1" or utc_now < snapshot["written_utc"]:
            raise ValueError("untrusted clock or snapshot")
        rows, anchors = snapshot["proofs"], snapshot["anchors"]
        if not isinstance(rows, list) or len(rows) > self.max_proofs or not isinstance(anchors, list) or len(anchors) > self.max_leases:
            raise ValueError("invalid snapshot bounds")
        proofs = {}
        for row in rows:
            valid_clock(row["expires_utc"])
            # Check original validity as well as remaining time after downtime.
            if not 0 <= row["expires_utc"]-snapshot["written_utc"] <= 604800:
                raise ValueError("invalid persisted expiry")
            if row["expires_utc"] <= utc_now:
                continue
            proof = self._record(row | {"remaining_ttl":row["expires_utc"]-utc_now}, now, utc_now, 0)
            if proof is None or proof.key in proofs:
                raise ValueError("invalid or duplicate persisted proof")
            proofs[proof.key] = proof
        restored_anchors = set()
        for anchor in anchors:
            if not isinstance(anchor, list) or len(anchor) != 2 or not isinstance(anchor[0], str):
                raise ValueError("invalid persisted alias root")
            restored_anchors.add((anchor[0], dns_name(anchor[1])))
        restored_anchors, leases = self._derive(proofs, restored_anchors, now)
        self.proofs, self.anchors, self.leases = proofs, restored_anchors, leases
