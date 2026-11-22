"""Optional native-page/ledger coordinator; no service or hook enrollment.

Caller must serialize ledger changes under the writer's existing locks and
publish only after qualified PF synchronization. External reload, source and
cleanup owners must invalidate/fence BEFORE their changes. This component does
not establish those lifecycle dependencies or authorize production DNS reuse.
"""
from contextlib import contextmanager
import time
from dnsalias.indexedproofs import CommitImpact,IndexedProofLedger
from dnsalias.confirmationkey import scope_name_keys,scope_policy_key


class ConfirmationAuthority:
    def __init__(self,native,publisher,*,available=None,answer_key=None):
        if available is not None and not callable(available):raise ValueError('explicit lifecycle qualifier required')
        if answer_key is not None and not callable(answer_key):raise ValueError('explicit qualified answer-key implementation required')
        self.native,self.publisher=native,publisher
        self.available=available;self.answer_key=answer_key
        self.state='new';self.horizon=None;self.invalidations=0
        self.writer=None;self.request=None;self.issued=False
        self.revocation_log=[]
        self.scope_enabled=all(callable(getattr(native,name,None)) for name in ('scope_add','scope_ready','scope_absent'))
        self.scope_seeded=False;self.scope_policies=None
        self.scope_exact=frozenset();self.scope_suffixes=()
        # An existing page/capability cannot silently become a new authority.
        try:
            if native.revoke(publisher)!=1:raise ValueError('fresh publisher required')
            self.state='revoked'
        except Exception:
            self.close();raise

    def invalidate(self):
        if self.state=='closed':return
        if self.state=='ready':
            try:
                self.native.revoke(self.publisher)
            except Exception:
                # An independently fenced page cannot be reactivated. Once
                # our own close has fenced it as well, ordinary synchronization
                # can continue without this optimization.
                self.close();return
            self.invalidations+=1
        self.state='revoked';self.horizon=None

    def before_commit(self,impact):
        if type(impact) is not CommitImpact:raise ValueError('qualified ledger preview required')
        if self.state=='closed':return  # Its old mapping is permanently fenced.
        if impact.replacement and self.scope_enabled:
            # A restored ledger can contain previously unseen CNAME targets.
            # Keep old bits, but require complete reseeding before any absence
            # proof can be used against the replacement.
            self.invalidate();self.scope_seeded=False;self.scope_policies=None
            try:self.native.scope_ready(self.publisher,False)
            except Exception:self.close();return
        if (impact.replacement or impact.policies_changed or impact.memberships_changed
            or impact.next_deadline is None or impact.next_expiry_utc is None
            or (self.horizon is not None and
                (impact.next_deadline<self.horizon[0] or impact.next_expiry_utc<self.horizon[1]))):
            if self.state=='ready' and len(self.revocation_log)<32:
                self.revocation_log.append({'monotonic':time.monotonic(),'prior_receipt_horizon':self.horizon,
                    'next_proof_horizon':(impact.next_deadline,impact.next_expiry_utc),
                    'memberships_changed':impact.memberships_changed,'policies_changed':impact.policies_changed,
                    'replacement':impact.replacement})
            self.invalidate()

    def bind(self,writer):
        from dnsalias.pfwriter import LeaseTableWriter
        if (self.writer is not None or not isinstance(writer,LeaseTableWriter)
            or writer.state!='ready' or writer.updates or writer.writer.total
            or writer.ledger._commit_observer!=self.before_commit
            or writer.confirmation is not self or self.state!='revoked'):
            raise ValueError('fresh writer with exact observed ledger required')
        self.writer=writer

    def prepare_scope(self,writer,event=None,policies=None):
        """Publish a monotone superset BEFORE a policy/dependency can change.

        Called by the sole writer inside its existing membership/reload locks.
        Retain every CNAME target reached from an alias, including expired
        ones. Previously unrelated graphs are traversed before an alias can
        start depending on them. False positives only retain the ACK wait.
        No TTL or membership is changed here and no resolver writes this page.
        """
        if not self.scope_enabled or self.state=='closed':return
        if writer is not self.writer or writer.state!='ready':raise ValueError('bound ready writer required')
        selected=writer.ledger.policies if policies is None else policies
        try:
            keys=[]
            if not self.scope_seeded or self.scope_policies is not selected:
                keys.extend(scope_policy_key(pattern) for policy in selected for pattern in policy.patterns)
                self.scope_exact=frozenset(pattern for policy in selected for pattern in policy.patterns if not pattern.startswith('*.'))
                self.scope_suffixes=tuple(pattern[1:] for policy in selected for pattern in policy.patterns if pattern.startswith('*.'))
            keys.extend(scope_name_keys(name)[0] for name in self._scope_dependencies(writer.ledger,event))
            for offset in range(0,len(keys),4096):
                self.native.scope_add(self.publisher,tuple(keys[offset:offset+4096]))
            if not self.scope_seeded:self.native.scope_ready(self.publisher,True)
            self.scope_seeded=True;self.scope_policies=selected
        except Exception:
            # Optional acceleration must be fenced before normal processing
            # continues. Never proceed with an incomplete interest index.
            self.close()

    def _scope_dependencies(self,ledger,event):
        """Conservative closure of old and proposed edges, before mutation."""
        pending=[root[1] for root in ledger.anchors] if not self.scope_seeded else []
        proposed={}
        if event is not None:
            query=event['qname'];rows=event['records']
            direct=query in self.scope_exact or query.endswith(self.scope_suffixes)
            for row in rows:
                if row['type']=='CNAME':proposed.setdefault(row['name'],set()).add(row['value'])
            if direct and (not self.scope_seeded or query not in ledger._roots or proposed):pending.append(query)
            if proposed and (direct or ledger._affected(set(proposed))):
                pending.extend(target for targets in proposed.values() for target in targets)
        visited=set();steps=0
        while pending:
            name=pending.pop()
            if name in visited:continue
            visited.add(name)
            for proof in ledger._owners.get(name,{}).values():
                steps+=1
                if steps>ledger.max_walk:raise OverflowError('scope dependency traversal bound exceeded')
                if proof.kind=='CNAME' and proof.value not in visited:pending.append(proof.value)
            pending.extend(proposed.get(name,()))
        return visited

    @contextmanager
    def for_reply(self,digest,qualified):
        """An authenticated caller binds one complete answer's digest.

        The private adapter must reject failed session/endpoint outcomes and
        revoke them before handling another query. The qualifier runs inside
        the writer locks immediately before publication. No startup replay,
        queued statistics event or unbound synchronization result can publish.
        """
        if (self.request is not None or type(digest) is not bytes or len(digest)!=32
            or not callable(qualified) or self.writer is None):
            raise ValueError('one bound qualified reply required')
        self.request=(digest,qualified);self.issued=False
        try:yield self
        except BaseException:
            self.close();raise
        finally:self.request=None

    def synchronized(self,writer,event,result,deadline):
        if self.state=='closed':return
        if (writer is not self.writer or writer.confirmation is not self
            or not writer._confirming or not writer._synchronizing or writer.state!='ready'):
            raise ValueError('publication must run inside the bound writer operation')
        if self.request is None:return
        digest,qualified=self.request
        now,utc=time.monotonic(),time.time()
        if not qualified() or (now>=deadline and not writer.allow_late_completion):
            self.invalidate();return
        if now>=deadline:
            # A persistent writer may finish an operation that started in
            # time. Its ledger already revoked affected receipts before any
            # membership change. A late completion cannot publish a receipt.
            return
        # Revalidate only this bounded answer, never scan the retained ledger.
        # The parser selects the complete reachable CNAME chain, so an expired
        # edge or zero-TTL address cannot borrow unrelated retained proofs.
        parsed=writer.ledger._parse_answer(event,now,utc)
        if parsed is None or not 1<=len(parsed[1])<=256:return
        if any(p.deadline<=now or p.expires_utc<=utc for p in parsed[1]):return
        keys=tuple(p.key for p in parsed[1])
        self.issued=self._publish(writer.ledger,digest,proof_keys=keys,synchronization=result)

    def _publish(self,ledger,digest,*,proof_keys,synchronization):
        """Caller supplies current answer's validated proof keys after PF sync.

        No proof scan: both expiry minima are indexed. Checking the current
        answer is bounded by its own records. A successful table operation alone
        is insufficient when the answer's proofs were zero-TTL or not committed.
        """
        if self.state=='closed':return False
        if self.available is not None:
            try:qualified=self.available() is True
            except Exception:qualified=False
            if not qualified:
                self.invalidate();return False
        if (self.writer is None or not self.writer._confirming or not self.writer._synchronizing
            or ledger is not self.writer.ledger or type(ledger) is not IndexedProofLedger or ledger._commit_observer!=self.before_commit
            or ledger._notifying or type(synchronization) is not dict
            or synchronization.get('memberships_synchronized') is not True):
            raise ValueError('bound committed ledger and completed synchronization required')
        if type(proof_keys) is not tuple or not 1<=len(proof_keys)<=256:
            raise ValueError('bounded current-answer proof keys required')
        if any(type(key) is not tuple or key not in ledger.proofs for key in proof_keys):
            return False
        mono,utc=ledger.expiry_horizon
        if mono is None or utc is None or synchronization.get('next_deadline')!=mono:
            return False
        # Only the optional reuse receipt ends slightly early. PF leases and
        # the DNS reply retain their exact original remaining TTL. This avoids
        # discarding every receipt for submillisecond clock-conversion changes
        # that still leave all receipts strictly inside their justifying leases.
        mono-=.001;utc-=.001
        if mono<=time.monotonic() or utc<=time.time():return False
        try:
            if self.state=='revoked':
                self.native.commit(self.publisher);self.state='ready'
            self.native.publish(self.publisher,digest,mono,utc)
        except Exception:
            # No automatic adoption or un-fencing. Caller can retain the normal
            # synchronous path once this owned mapping is permanently disabled.
            self.close();return False
        self.horizon=(mono,utc) if self.horizon is None else (
            max(self.horizon[0],mono),max(self.horizon[1],utc))
        return True

    def close(self):
        if self.state!='closed':
            self.native.close(self.publisher)
            self.state='closed';self.horizon=None
