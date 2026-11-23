"""Incremental pure proof ledger for the eventual DNS-to-PF path.

No native access or trust establishment. Uses the same answer parser, CNAME
derivation and persisted format as ProofLedger. observe_changes/expire_changes
return only changed memberships and leases; compatibility observe/tables return
full results and are intended for offline callers. One owner thread is required.
Never edit proofs/anchors/leases directly: the indexes belong to this ledger.

An indexed expiry heap contains exactly one entry per proof. A changed owner
recalculates only roots reachable through earlier CNAME edges. All staging,
capacity and traversal validation precedes commit, including expiry removal.
Shared IP counts combine every independent lease inside each separate policy.
"""
from collections import defaultdict
from dataclasses import dataclass
import heapq

from .leases import Lease, Policy, valid_clock
from .proofs import ProofLedger, _lease_identity


@dataclass(frozen=True)
class CommitImpact:
    """Preview delivered before mutation, never proof of completed PF sync."""
    policies_changed: bool
    memberships_changed: bool
    next_deadline: float | None
    next_expiry_utc: float | None
    replacement: bool = False


class _Deadlines:
    def __init__(self):self.heap=[];self.positions={}

    def _swap(self,a,b):
        self.heap[a],self.heap[b]=self.heap[b],self.heap[a]
        self.positions[self.heap[a][1]]=a;self.positions[self.heap[b][1]]=b

    def _up(self,index):
        while index:
            parent=(index-1)//2
            if self.heap[parent]<=self.heap[index]:break
            self._swap(parent,index);index=parent
        return index

    def _down(self,index):
        while 2*index+1<len(self.heap):
            child=2*index+1
            if child+1<len(self.heap) and self.heap[child+1]<self.heap[child]:child+=1
            if self.heap[index]<=self.heap[child]:break
            self._swap(index,child);index=child

    def set(self,key,deadline):
        if key in self.positions:
            index=self.positions[key];self.heap[index]=(deadline,key)
            self._down(self._up(index))
        else:
            self.positions[key]=len(self.heap);self.heap.append((deadline,key));self._up(len(self.heap)-1)

    def remove(self,key):
        index=self.positions.pop(key);last=self.heap.pop()
        if index<len(self.heap):
            self.heap[index]=last;self.positions[last[1]]=index;self._down(self._up(index))

    def remove_many(self,keys):
        # Dense expiry batches are cheaper to compact/heapify once than to
        # repair the heap for every key. Both indexes still have one entry per
        # live proof; there are no stale deadlines waiting for later cleanup.
        if not keys:return
        if not keys<=self.positions.keys():raise KeyError('unknown deadline key')
        if len(keys)>=32 and len(keys)*8>=len(self.heap):
            remaining=[entry for entry in self.heap if entry[1] not in keys]
            heapq.heapify(remaining)
            self.heap=remaining;self.positions={entry[1]:i for i,entry in enumerate(remaining)}
        else:
            for key in keys:self.remove(key)

    def due(self,now):
        # Inspect due subtrees without changing anything during staging.
        result=set();pending=[0] if self.heap else []
        while pending:
            index=pending.pop()
            if index>=len(self.heap) or self.heap[index][0]>now:continue
            result.add(self.heap[index][1]);pending.extend((2*index+1,2*index+2))
        return result

    @property
    def next(self):return self.heap[0][0] if self.heap else None

    def minimum_without(self,keys):
        """Preview staged removals without copying/scanning the entire heap.

        The first retained minimum bounds every descendant. Only excluded
        ancestors need expansion, so work scales with the changed keys.
        """
        if not self.heap:return None
        pending=[(self.heap[0][0],0)]
        while pending:
            value,index=heapq.heappop(pending)
            if self.heap[index][1] not in keys:return value
            for child in (2*index+1,2*index+2):
                if child<len(self.heap):heapq.heappush(pending,(self.heap[child][0],child))
        return None


class _OwnerView:
    def __init__(self,current,staged):self.current,self.staged=current,staged
    def get(self,name,default=()):
        bucket=self.staged[name] if name in self.staged else self.current.get(name)
        return bucket.values() if bucket else default


class _PolicyRoots:
    """Map a canonical query to matching policy roots. Only configuration is stored."""

    def __init__(self, policies):
        self.exact = {}
        self.suffixes = {}
        self.scan = []
        for policy in policies:
            if type(policy) is not Policy or (len(policies) <= 4 and len(policy._suffixes) < 32):
                self.scan.append(policy)
                continue
            for pattern in policy._exact:
                self.exact.setdefault(pattern, []).append(policy.name)
            for suffix in set(policy._suffixes):
                self.suffixes.setdefault(suffix, []).append(policy.name)
        self.suffix_depths = {suffix.count(".") for suffix in self.suffixes}
        self.max_suffix_depth = max(self.suffix_depths, default=0)

    def matching(self, query):
        roots = {(p.name, query) for p in self.scan if p.matches(query)}
        for name in self.exact.get(query, ()):
            roots.add((name, query))
        # A wildcard can match only at its configured label depth. Starting at
        # the right bounds the work even for names with many leading labels.
        end = len(query)
        for depth in range(1, self.max_suffix_depth + 1):
            end = query.rfind(".", 0, end)
            if end < 0:
                break
            if depth in self.suffix_depths:
                for name in self.suffixes.get(query[end:], ()):
                    roots.add((name, query))
        return roots


class IndexedProofLedger(ProofLedger):
    def __init__(self,*args,before_commit=None,**kwargs):
        if before_commit is not None and not callable(before_commit):
            raise ValueError('explicit commit observer required')
        self._commit_observer=before_commit;self._notifying=False
        super().__init__(*args,**kwargs);self._reindex()

    def _reindex(self):
        self._policy_roots = _PolicyRoots(self.policies)
        self._owners={};self._parents={};self._roots={};self._root_leases={}
        self._members={p.name:{} for p in self.policies};self._deadlines=_Deadlines()
        # No second index or callback work for the ordinary, disabled path.
        self._utc_deadlines=_Deadlines() if self._commit_observer is not None else None
        for proof in self.proofs.values():self._insert_proof(proof)
        for anchor in self.anchors:self._roots.setdefault(anchor[1],set()).add(anchor)
        for key,lease in self.leases.items():
            self._root_leases.setdefault((lease.policy,lease.name),{})[key]=lease
            counts=self._members[lease.policy];counts[lease.address]=counts.get(lease.address,0)+1

    def _insert_proof(self,proof):
        self._owners.setdefault(proof.name,{})[proof.key]=proof
        self._deadlines.set(proof.key,proof.deadline)
        if self._utc_deadlines is not None:self._utc_deadlines.set(proof.key,proof.expires_utc)
        if proof.kind=='CNAME':
            parents=self._parents.setdefault(proof.value,{})
            parents[proof.name]=parents.get(proof.name,0)+1

    def _remove_proof(self,proof,*,deadline=True):
        bucket=self._owners[proof.name];del bucket[proof.key]
        if not bucket:del self._owners[proof.name]
        if deadline:self._deadlines.remove(proof.key)
        if deadline and self._utc_deadlines is not None:self._utc_deadlines.remove(proof.key)
        if proof.kind=='CNAME':
            parents=self._parents[proof.value];parents[proof.name]-=1
            if not parents[proof.name]:del parents[proof.name]
            if not parents:del self._parents[proof.value]

    @property
    def expiry_horizon(self):
        """O(1) conservative minima; observation must be enabled at creation."""
        if self._utc_deadlines is None:raise ValueError('commit observation is not enabled')
        return self._deadlines.next,self._utc_deadlines.next

    def _notify(self,impact):
        if self._notifying:raise RuntimeError('commit observers must not mutate the ledger')
        self._notifying=True
        try:self._commit_observer(impact)
        finally:self._notifying=False

    def _before_commit(self,expired,updates,*,policies_changed=False,memberships_changed=False):
        if self._commit_observer is None:return
        excluded=expired|updates.keys()
        mono=self._deadlines.minimum_without(excluded)
        utc=self._utc_deadlines.minimum_without(excluded)
        for proof in updates.values():
            mono=proof.deadline if mono is None else min(mono,proof.deadline)
            utc=proof.expires_utc if utc is None else min(utc,proof.expires_utc)
        self._notify(CommitImpact(policies_changed,memberships_changed,mono,utc))

    def _before_replacement(self,staged,*,memberships_changed):
        if self._commit_observer is None:return
        # Restore / replacing the policy set is already occasional O(N) work;
        # the per-reply and ordinary expiry paths use the indexed preview above.
        self._notify(CommitImpact(self.policies!=staged.policies,memberships_changed,
            min((p.deadline for p in staged.proofs.values()),default=None),
            min((p.expires_utc for p in staged.proofs.values()),default=None),True))

    def _affected(self,owners):
        visited=set();pending=list(owners);roots=set();steps=0
        while pending:
            name=pending.pop()
            if name in visited:continue
            visited.add(name);roots.update(self._roots.get(name,()))
            for parent in self._parents.get(name,()):
                steps+=1
                if steps>self.max_walk:raise OverflowError('reverse CNAME traversal budget exceeded')
                if parent not in visited:pending.append(parent)
        return roots

    @staticmethod
    def _empty_change(next_deadline):
        return {'tables_added':{},'tables_removed':{},'leases_upserted':(),
            'leases_removed':(),'next_deadline':next_deadline,'affected_roots':0}

    def _direct_changes(self,owners,updates,expired):
        """Change direct proofs without rebuilding unaffected valid leases.

        Only used without policy/new-root changes or incoming/outgoing CNAME
        edges. The general graph path handles those cases. Expiry removes only
        the exact independent mapping, including when another mapping still
        justifies the same IP. Retained generations keep original deadlines.
        """
        sizes={name:len(self._owners.get(name,{})) for name in owners}
        roots={root for name in owners for root in self._roots.get(name,())}
        old={};derived={};counts=defaultdict(int)
        for key in expired:
            proof=self.proofs[key];sizes[proof.name]-=1
            for policy,root in self._roots.get(proof.name,()):
                lease_key=(policy,root,proof.value,_lease_identity((key,)))
                old[lease_key]=self.leases[lease_key]
        for key,proof in updates.items():
            if key not in self.proofs or key in expired:sizes[proof.name]+=1
        if sum(sizes[name]*len(self._roots.get(name,())) for name in owners)>self.max_walk:
            raise OverflowError('proof traversal budget exceeded')
        for proof in updates.values():
            identity=_lease_identity((proof.key,))
            for policy,root in self._roots.get(proof.name,()):
                key=(policy,root,proof.value,identity)
                derived[key]=Lease(policy,root,proof.value,identity,proof.deadline,proof.expires_utc,(root,))
                if key not in self.leases:counts[(policy,proof.value)]+=1
        removed=tuple(key for key in old if key not in derived)
        if len(self.leases)-len(removed)+sum(counts.values())>self.max_leases:
            raise OverflowError('derived lease capacity exceeded')
        for key in removed:
            lease=old[key];counts[(lease.policy,lease.address)]-=1
        added={};removed_ips={}
        for (policy,address),delta in counts.items():
            prior=self._members[policy].get(address,0);after=prior+delta
            if after<0:raise RuntimeError('inconsistent private membership index')
            if prior==0 and after>0:added.setdefault(policy,set()).add(address)
            if prior>0 and after==0:removed_ips.setdefault(policy,set()).add(address)
        # Everything above is staged. Existing proof keys may shorten, never
        # extend, their deadline; different generations remain independent.
        self._before_commit(expired,updates,memberships_changed=bool(added or removed_ips))
        self._deadlines.remove_many(expired)
        if self._utc_deadlines is not None:self._utc_deadlines.remove_many(expired)
        for key in expired:self._remove_proof(self.proofs.pop(key),deadline=False)
        for key,proof in updates.items():
            if key in self.proofs:self._remove_proof(self.proofs[key])
            self.proofs[key]=proof;self._insert_proof(proof)
        for key in removed:
            lease=self.leases.pop(key);self._root_leases[(lease.policy,lease.name)].pop(key)
        for key,lease in derived.items():
            self.leases[key]=lease;self._root_leases[(lease.policy,lease.name)][key]=lease
        for root in roots:
            if not sizes[root[1]]:
                self.anchors.remove(root);self._roots[root[1]].remove(root);self._root_leases.pop(root)
                if not self._roots[root[1]]:del self._roots[root[1]]
        for (policy,address),delta in counts.items():
            members=self._members[policy];after=members.get(address,0)+delta
            if after:members[address]=after
            else:members.pop(address,None)
        return {'tables_added':added,'tables_removed':removed_ips,'leases_upserted':tuple(derived.values()),
            'leases_removed':removed,'next_deadline':self._deadlines.next,'affected_roots':len(roots)}

    def _apply(self,parsed_answer,now,*,policies=None):
        if self._notifying:raise RuntimeError('commit observers must not mutate the ledger')
        if parsed_answer is None and policies is None:
            next_deadline = self._deadlines.next
            if next_deadline is None or next_deadline > now:
                return self._empty_change(next_deadline)
        # Policy edits are occasional owner-loop work. They may change matching
        # names, never table identities. New roots require a subsequent actual
        # query; a retained CNAME owner is not evidence it was queried itself.
        walker=self if policies is None else ProofLedger(policies,self.max_proofs,self.max_leases,self.max_walk)
        invalid_roots=set()
        if policies is not None:
            policy_by_name={p.name:p for p in walker.policies}
            if policy_by_name.keys()!=self._members.keys():raise ValueError('policy edits cannot change table identities')
            invalid_roots={root for root in self.anchors if not policy_by_name[root[0]].matches(root[1])}
            edited_roots = _PolicyRoots(walker.policies)
        expired=self._deadlines.due(now);updates={}
        query,parsed=parsed_answer if parsed_answer is not None else (None,())
        for proof in parsed:
            prior=updates.get(proof.key) or (self.proofs.get(proof.key) if proof.key not in expired else None)
            if prior and prior.deadline<proof.deadline:proof=prior
            updates[proof.key]=proof
        expired|={key for key,proof in updates.items() if proof.deadline<=now and key in self.proofs}
        updates={key:proof for key,proof in updates.items() if proof.deadline>now}
        added=sum(key not in self.proofs or key in expired for key in updates)
        if len(self.proofs)-len(expired)+added>self.max_proofs:raise OverflowError('proof capacity exceeded')
        # Ignore unchanged cache proofs: no stale heap entries or full scans.
        updates={key:proof for key,proof in updates.items() if key in expired or self.proofs.get(key)!=proof}
        owners={self.proofs[key].name for key in expired}|{p.name for p in updates.values()}
        new_roots=self._policy_roots.matching(query)-self.anchors if query is not None else set()
        if not owners and not new_roots and not invalid_roots:
            if policies is not None:
                if walker.policies!=self.policies:
                    self._before_commit(set(),{},policies_changed=True)
                self.policies, self._policy_roots = walker.policies, edited_roots
            return self._empty_change(self._deadlines.next)
        if (policies is None and not new_roots
                and all(not self._parents.get(name) for name in owners)
                and all(p.kind in ('A','AAAA') for p in updates.values())
                and all(p.kind in ('A','AAAA') for name in owners for p in self._owners.get(name,{}).values())):
            return self._direct_changes(owners,updates,expired)
        affected=self._affected(owners)|new_roots|invalid_roots
        staged={name:dict(self._owners.get(name,{})) for name in owners}
        for key in expired:staged[self.proofs[key].name].pop(key)
        for key,proof in updates.items():staged[proof.name][key]=proof
        active,derived=walker._walk(_OwnerView(self._owners,staged),affected)
        old={key:lease for root in affected for key,lease in self._root_leases.get(root,{}).items()}
        if len(self.anchors)-len(affected&self.anchors)+len(active)>self.max_leases:raise OverflowError('alias root capacity exceeded')
        if len(self.leases)-len(old)+len(derived)>self.max_leases:raise OverflowError('derived lease capacity exceeded')
        removed=tuple(key for key in old if key not in derived)
        upserted=tuple(lease for key,lease in derived.items() if old.get(key)!=lease)
        counts=defaultdict(int)
        for key in removed:
            lease=old[key];counts[(lease.policy,lease.address)]-=1
        for key,lease in derived.items():
            if key not in old:counts[(lease.policy,lease.address)]+=1
        tables_added={};tables_removed={}
        for (policy,address),delta in counts.items():
            prior=self._members[policy].get(address,0);after=prior+delta
            if after<0:raise RuntimeError('inconsistent private membership index')
            if prior==0 and after>0:tables_added.setdefault(policy,set()).add(address)
            if prior>0 and after==0:tables_removed.setdefault(policy,set()).add(address)
        # Commit after all bounded parsing, graph derivation and capacity checks.
        self._before_commit(expired,updates,policies_changed=walker.policies!=self.policies,
            memberships_changed=bool(tables_added or tables_removed))
        if policies is not None:
            self.policies, self._policy_roots = walker.policies, edited_roots
        self._deadlines.remove_many(expired)
        if self._utc_deadlines is not None:self._utc_deadlines.remove_many(expired)
        for key in expired:
            self._remove_proof(self.proofs.pop(key),deadline=False)
        for key,proof in updates.items():
            if key in self.proofs:self._remove_proof(self.proofs[key])
            self.proofs[key]=proof;self._insert_proof(proof)
        for root in affected:
            if root in self.anchors:
                self.anchors.remove(root);self._roots[root[1]].remove(root)
                if not self._roots[root[1]]:del self._roots[root[1]]
            self._root_leases.pop(root,None)
        for root in active:self.anchors.add(root);self._roots.setdefault(root[1],set()).add(root)
        for key in old:self.leases.pop(key)
        for key,lease in derived.items():
            self.leases[key]=lease;self._root_leases.setdefault((lease.policy,lease.name),{})[key]=lease
        for (policy,address),delta in counts.items():
            after=self._members[policy].get(address,0)+delta
            if after:self._members[policy][address]=after
            else:self._members[policy].pop(address,None)
        return {'tables_added':tables_added,'tables_removed':tables_removed,'leases_upserted':upserted,
            'leases_removed':removed,'next_deadline':self._deadlines.next,'affected_roots':len(affected)}

    def observe_changes(self,event,now,utc_now):
        parsed=self._parse_answer(event,now,utc_now)
        # Preserve the reference ledger's negative-answer behavior. Independent
        # expiry polling still removes positive leases at their own deadlines.
        if parsed is None:return self._empty_change(self._deadlines.next)
        return self._apply(parsed,now)

    def observe(self,event,now,utc_now):
        parsed=self._parse_answer(event,now,utc_now)
        if parsed is None:return []
        self._apply(parsed,now);return list(self.leases.values())

    def expire_changes(self,now):
        valid_clock(now);return self._apply(None,now)

    def reconfigure_changes(self,policies,now):
        """Edit patterns on fixed tables without renewing any proof or lease.

        Remove only roots no longer selected, preserving every independent
        justifying mapping for shared addresses. Newly selected names enter on
        a new trusted reply (an ordinary cache lookup is sufficient). No cache
        dump, inferred CNAME query, new table, timer or external mutation.
        Staging errors preserve the complete original ledger and policy set.
        """
        valid_clock(now)
        return self._apply(None,now,policies=tuple(policies))

    def _derive_for_edit(self, staged, now):
        if self._parents:
            return staged._derive(staged.proofs, self.anchors, now)
        # Without CNAME edges, each lease has exactly one address proof.
        # A policy edit can only remove existing roots and expired leases.
        policies = {policy.name: policy for policy in staged.policies}
        live_names = {proof.name for proof in staged.proofs.values()}
        anchors = {(policy, name) for policy, name in self.anchors
                   if name in live_names and policy in policies and policies[policy].matches(name)}
        if len(anchors) > staged.max_leases:
            raise OverflowError("alias root capacity exceeded")
        leases = {key: lease for key, lease in self.leases.items()
                  if lease.deadline > now and (lease.policy, lease.name) in anchors}
        if len(leases) > staged.max_walk:
            raise OverflowError("proof traversal budget exceeded")
        if len(leases) > staged.max_leases:
            raise OverflowError("derived lease capacity exceeded")
        return anchors, leases

    def replace_policy_set(self,policies,now):
        """Configuration edit, retaining independent proofs and their deadlines.

        New policy identities learn from subsequent replies. Existing identities
        retain every still-valid, still-selected mapping. No TTL is renewed.
        This operation runs only when the saved policy set changes.
        """
        if self._notifying:raise RuntimeError('commit observers must not mutate the ledger')
        valid_clock(now)
        staged=ProofLedger(tuple(policies),self.max_proofs,self.max_leases,self.max_walk)
        staged.proofs={k:p for k,p in self.proofs.items() if p.deadline>now}
        staged.anchors, staged.leases = self._derive_for_edit(staged, now)
        before={name:set(values) for name,values in self._members.items()}
        after={p.name:set() for p in staged.policies}
        for lease in staged.leases.values():after[lease.policy].add(lease.address)
        names=set(before)|set(after)
        change={'tables_added':{n:after.get(n,set())-before.get(n,set()) for n in names},
                'tables_removed':{n:before.get(n,set())-after.get(n,set()) for n in names}}
        self._before_replacement(staged,memberships_changed=before!=after)
        self.policies,self.proofs,self.anchors,self.leases=staged.policies,staged.proofs,staged.anchors,staged.leases
        self._reindex()
        return change

    def expire(self,now):self.expire_changes(now)

    def tables(self,now):
        self.expire(now);return {name:set(values) for name,values in self._members.items()}

    def restore(self,snapshot,now,utc_now,trusted_clock=False):
        if self._notifying:raise RuntimeError('commit observers must not mutate the ledger')
        staged=ProofLedger(self.policies,self.max_proofs,self.max_leases,self.max_walk)
        staged.restore(snapshot,now,utc_now,trusted_clock)
        # Replacement invalidates prior confirmations even when memberships
        # happen to be identical; it is not a hot-path delta operation.
        self._before_replacement(staged,memberships_changed=self.leases!=staged.leases)
        self.proofs,self.anchors,self.leases=staged.proofs,staged.anchors,staged.leases
        self._reindex()
