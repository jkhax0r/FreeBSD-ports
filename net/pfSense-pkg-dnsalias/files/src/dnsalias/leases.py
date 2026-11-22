"""Pure lease engine. No network, process, filesystem or PF access.

Input is an adapter-normalized trusted reply, NOT raw SWIG TTL fields. Adapters
must prove the TTL basis and supply a stable answer_id across cache hits.
"""
from dataclasses import dataclass
from functools import lru_cache
import ipaddress
import math
import re


def dns_name(value):
    if not isinstance(value, str) or not value or len(value) > 254:
        raise ValueError("invalid DNS name")
    return _dns_name(value) if type(value) is str else _dns_name.__wrapped__(value)


@lru_cache(maxsize=16384)
def _dns_name(value):
    # Only bounded strings enter this cache; no TTL, policy or trust result.
    name = (value[:-1] if value.endswith(".") else value).encode("idna").decode("ascii").lower()
    if len(name) > 253 or any(not re.fullmatch(r"[a-z0-9_-]{1,63}", x) for x in name.split(".")):
        raise ValueError("invalid DNS label")
    return name


def valid_clock(*values):
    if any(isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x) for x in values):
        raise ValueError("invalid clock")


def answer_identity(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,128}", value):
        raise ValueError("invalid answer identity")
    return value


def admissible_address(value):
    address = ipaddress.ip_address(value)
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        raise ValueError("sinkhole or non-destination address")
    return str(address)


@dataclass(frozen=True)
class Policy:
    name: str
    patterns: tuple

    def __post_init__(self):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,22}", self.name):
            raise ValueError("policy name must be a bounded identifier")
        normalized = []
        for p in self.patterns:
            wildcard = p.startswith("*.")
            normalized.append(("*." if wildcard else "") + dns_name(p[2:] if wildcard else p))
        if not normalized or len(normalized) > 256:
            raise ValueError("policy requires 1..256 exact names or suffix patterns")
        object.__setattr__(self, "patterns", tuple(normalized))
        object.__setattr__(self, "_exact", frozenset(p for p in normalized if not p.startswith('*.')))
        object.__setattr__(self, "_suffixes", tuple(p[1:] for p in normalized if p.startswith('*.')))

    def matches(self, name):
        name = dns_name(name)
        return name in self._exact or name.endswith(self._suffixes)


@dataclass(frozen=True)
class Lease:
    policy: str
    name: str
    address: str
    answer_id: str
    deadline: float
    expires_utc: float
    cname_path: tuple


class LeaseEngine:
    def __init__(self, policies, max_leases=100000):
        self.policies = tuple(policies)
        if len(self.policies) > 128 or len({p.name for p in self.policies}) != len(self.policies):
            raise ValueError("duplicate or excessive policies")
        if type(max_leases) is not int or not 1 <= max_leases <= 100000:
            raise ValueError("invalid lease limit")
        self.max_leases = max_leases
        self.leases = {}

    def expire(self, now):
        valid_clock(now)
        for key in [k for k, v in self.leases.items() if v.deadline <= now]:
            del self.leases[key]

    def tables(self, now):
        self.expire(now)
        result = {p.name: set() for p in self.policies}
        for lease in self.leases.values():
            result[lease.policy].add(lease.address)
        return result

    def observe(self, event, now, utc_now):
        """Commit a whole validated answer atomically; return created leases.

        A cache hit with the same answer identity can shorten, never extend,
        that generation's deadline. A genuinely new answer gets a new identity.
        Older independent generations remain until their own deadlines.
        """
        valid_clock(now, utc_now)
        if event.get("trusted") is not True or event.get("ttl_basis") != "remaining":
            raise ValueError("trusted reply with verified remaining TTLs required")
        if event.get("stale") is not False:
            raise ValueError("stale/unknown freshness is not admitted in v0.1")
        if event.get("rcode") != "NOERROR":
            return []
        query = dns_name(event["qname"])
        generation = answer_identity(event["answer_id"])
        observed = event["observed_utc"]
        if isinstance(observed, bool) or not isinstance(observed, (int, float)) or not math.isfinite(observed):
            raise ValueError("invalid observation time")
        age = utc_now-observed
        if age < 0 or age > 604800:
            raise ValueError("clock ambiguity or excessive delivery delay")
        records = event["records"]
        if not isinstance(records, list) or len(records) > 2048:
            raise ValueError("oversized answer")
        addresses, aliases = {}, {}
        for rr in records:
            kind = rr["type"]
            if kind not in ("A", "AAAA", "CNAME"):
                continue
            owner = dns_name(rr["name"])
            ttl = rr["remaining_ttl"]
            if isinstance(ttl, bool) or not isinstance(ttl, (int, float)) or not math.isfinite(ttl) or not 0 <= ttl <= 604800:
                raise ValueError("invalid normalized TTL")
            ttl = max(0, ttl-age)
            if kind == "CNAME":
                target = dns_name(rr["value"])
                if owner in aliases and aliases[owner][0] != target:
                    raise ValueError("conflicting CNAME targets")
                aliases[owner] = (target, min(ttl, aliases.get(owner, (target, ttl))[1]))
            else:
                address = ipaddress.ip_address(rr["value"])
                if address.version != (4 if kind == "A" else 6):
                    raise ValueError("address family mismatch")
                if address.is_unspecified or address.is_multicast or address.is_loopback:
                    continue
                addresses.setdefault(owner, []).append((str(address), ttl))
        node, chain, lifetime = query, [], float("inf")
        while node in aliases:
            if node in chain or len(chain) >= 16 or node in addresses:
                raise ValueError("invalid CNAME chain")
            chain.append(node)
            node, edge_ttl = aliases[node]
            lifetime = min(lifetime, edge_ttl)
        if node in chain:
            raise ValueError("CNAME loop")
        chain.append(node)
        candidates = {}
        for policy in self.policies:
            if not policy.matches(query):
                continue
            for address, ttl in addresses.get(node, ()):
                ttl = min(ttl, lifetime)
                if ttl <= 0:
                    continue
                key = (policy.name, query, address, generation)
                lease = Lease(policy.name, query, address, generation, now+ttl, utc_now+ttl, tuple(chain))
                # A duplicate RR is bounded by its shortest validity.
                prior = candidates.get(key) or self.leases.get(key)
                if prior and prior.deadline < lease.deadline:
                    lease = prior
                candidates[key] = lease
        # No partially committed answer when capacity is exhausted.
        active = {k:v for k,v in self.leases.items() if v.deadline > now}
        if len(set(active) | set(candidates)) > self.max_leases:
            raise OverflowError("lease capacity exceeded")
        active.update(candidates)
        self.leases = active
        return list(candidates.values())

    def snapshot(self, now, utc_now):
        valid_clock(now, utc_now)
        self.expire(now)
        return {"version": 1, "written_utc": utc_now, "leases": [
            {"policy": x.policy, "name": x.name, "address": x.address,
             "answer_id": x.answer_id, "expires_utc": utc_now+(x.deadline-now),
             "cname_path": list(x.cname_path)} for x in self.leases.values()]}

    def restore(self, snapshot, now, utc_now, trusted_clock=False):
        # Refuse boot restoration without an explicit trustworthy clock.
        valid_clock(now, utc_now, snapshot["written_utc"])
        if trusted_clock is not True or snapshot.get("version") != 1 or utc_now < snapshot["written_utc"]:
            raise ValueError("untrusted clock or snapshot")
        if not isinstance(snapshot["leases"], list) or len(snapshot["leases"]) > self.max_leases:
            raise ValueError("invalid snapshot size")
        restored = {}
        by_name = {p.name:p for p in self.policies}
        for item in snapshot["leases"]:
            policy = by_name.get(item["policy"])
            if not policy or not policy.matches(item["name"]):
                continue
            valid_clock(item["expires_utc"])
            ttl = item["expires_utc"]-utc_now
            if not math.isfinite(ttl) or ttl > 604800:
                raise ValueError("invalid persisted expiry")
            if ttl <= 0:
                continue
            name, address = dns_name(item["name"]), admissible_address(item["address"])
            identity = answer_identity(item["answer_id"])
            path = item["cname_path"]
            if not isinstance(path, list) or not 1 <= len(path) <= 17:
                raise ValueError("invalid persisted CNAME path")
            path = tuple(dns_name(n) for n in path)
            if path[0] != name or len(set(path)) != len(path):
                raise ValueError("invalid persisted CNAME path")
            key = (policy.name, name, address, identity)
            candidate = Lease(policy.name, name, address, identity, now+ttl, item["expires_utc"], path)
            prior = restored.get(key)
            restored[key] = prior if prior and prior.deadline <= candidate.deadline else candidate
        if len(restored) > self.max_leases:
            raise OverflowError("snapshot exceeds capacity")
        self.leases = restored
