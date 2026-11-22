import copy
import random
import unittest
from unittest.mock import patch

from dnsalias.indexedproofs import IndexedProofLedger,_Deadlines
from dnsalias.leases import Policy
from dnsalias.proofs import ProofLedger
import test_proofs as fixtures


class IndexedExistingBehaviorTests(fixtures.ProofTests):
    def setUp(self):
        self.ledger=IndexedProofLedger([Policy('media',('a.zone.example.com','b.zone.example.com')),Policy('other',('b.zone.example.com',))])


class IndexedProofDeltaTests(unittest.TestCase):
    def test_indexed_patterns_after_edit_replace_and_restore(self):
        policies = [
            Policy('apex', ('EXAMPLE.com.',)),
            Policy('children', ('*.example.com', '*.example.com')),
            Policy('both', ('*.deep.example.com', 'host.deep.example.com')),
            Policy('deep', ('deep.example.com',)),
            Policy('empty', ('unused.example.com',)),
        ]
        ledger = IndexedProofLedger(policies)

        def observe(name, expected, now):
            reply = fixtures.answer(name, [fixtures.record(name, '192.0.2.1', 30, 'rr')], now)
            ledger.observe_changes(reply, now, 1000 + now)
            self.assertEqual({policy for policy, root in ledger.anchors if root == name.lower().rstrip('.')},
                             set(expected))

        observe('EXAMPLE.com.', ['apex'], 0)
        observe('Deep.example.com.', ['children', 'deep'], 0)
        observe('host.deep.example.com', ['children', 'both'], 0)
        observe('x.' * 100 + 'deep.example.com', ['children', 'both'], 0)
        observe('notdeep.example.com', ['children'], 0)
        edited = [Policy('apex', ('new.example.com',)), *policies[1:]]
        ledger.reconfigure_changes(edited, 1)
        observe('example.com', [], 1)
        observe('new.example.com', ['apex', 'children'], 1)
        ledger.replace_policy_set(edited[:-1] + [Policy('added', ('*.deep.example.com',))], 2)
        state = ledger.snapshot(2, 1002)
        ledger.restore(state, 3, 1003, trusted_clock=True)
        observe('another.deep.example.com', ['added', 'both', 'children'], 3)

    def test_idle_expiry_keeps_observer_and_deadline_semantics(self):
        notifications = []
        ledger = IndexedProofLedger([Policy('one', ('example.com',))], before_commit=notifications.append)
        self.assertIsNone(ledger.expire_changes(0)['next_deadline'])
        reply = fixtures.answer('example.com', [fixtures.record('example.com', '192.0.2.1', 5, 'rr')])
        ledger.observe_changes(reply, 0, 1000)
        notifications.clear()
        self.assertEqual(ledger.expire_changes(4.999)['next_deadline'], 5)
        self.assertEqual(notifications, [])
        with self.assertRaises(ValueError):
            ledger.expire_changes(float('nan'))
        self.assertEqual(ledger.expire_changes(5)['tables_removed'], {'one': {'192.0.2.1'}})
        self.assertEqual(len(notifications), 1)

    def test_submicrosecond_shortening_preserves_graph_and_shared_ip_expiry(self):
        reference,indexed=self.pair()
        initial=[fixtures.answer('a.zone.example.com',[
            fixtures.record('a.zone.example.com','cdn.zone.example.com',20,'edge','CNAME'),
            fixtures.record('cdn.zone.example.com','192.0.2.7',10,'address')]),
            fixtures.answer('b.zone.example.com',[fixtures.record('b.zone.example.com','192.0.2.7',30,'independent')])]
        for event in initial:
            reference.observe(event,0,1000);indexed.observe_changes(event,0,1000)
        parents=copy.deepcopy(indexed._parents)
        for step in range(1,9):
            now=step*.5;shortening=step*.0000002
            event=fixtures.answer('a.zone.example.com',[
                fixtures.record('a.zone.example.com','cdn.zone.example.com',20-now-shortening,'edge','CNAME'),
                fixtures.record('cdn.zone.example.com','192.0.2.7',10-now-shortening,'address')],now)
            reference.observe(event,now,1000+now);change=indexed.observe_changes(event,now,1000+now)
            self.check_state(reference,indexed)
            self.assertEqual(indexed._parents,parents)
            self.assertFalse(change['tables_added']);self.assertFalse(change['tables_removed'])
            self.assertEqual(len(indexed._deadlines.heap),3)
            for proof in indexed.proofs.values():
                if proof.identity=='address':self.assertLess(proof.deadline,10)
        earliest=min(p.deadline for p in indexed.proofs.values())
        reference.expire(earliest);indexed.expire_changes(earliest);self.check_state(reference,indexed)
        self.assertEqual(indexed.tables(earliest),{'all':{'192.0.2.7'},'root':{'192.0.2.7'}})
        reference.expire(30);indexed.expire_changes(30);self.check_state(reference,indexed)
        self.assertTrue(all(not members for members in indexed.tables(30).values()))

    def test_policy_edit_preserves_independent_shared_leases_and_original_deadlines(self):
        ledger=IndexedProofLedger([Policy('one',('a.zone.example.com','b.zone.example.com')),Policy('two',('a.zone.example.com',))])
        for name,ttl in (('a.zone.example.com',5),('b.zone.example.com',30)):
            ledger.observe_changes(fixtures.answer(name,[fixtures.record(name,'192.0.2.7',ttl,name)]),0,1000)
        proofs=copy.deepcopy(ledger.proofs)
        change=ledger.reconfigure_changes([Policy('one',('b.zone.example.com',)),Policy('two',('a.zone.example.com',))],2)
        self.assertFalse(change['tables_removed']);self.assertEqual(ledger.proofs,proofs)
        self.assertEqual({l.name for l in ledger.leases.values() if l.policy=='one'},{'b.zone.example.com'})
        self.assertEqual(ledger.expire_changes(5)['tables_removed'],{'two':{'192.0.2.7'}})
        self.assertEqual(ledger.tables(29),{'one':{'192.0.2.7'},'two':set()})
        self.assertEqual(ledger.expire_changes(30)['tables_removed'],{'one':{'192.0.2.7'}})

    def test_new_patterns_need_actual_question_and_do_not_infer_cname_owner_query(self):
        ledger=IndexedProofLedger([Policy('one',('a.zone.example.com',))])
        event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','cdn.zone.example.com',60,'edge','CNAME'),
            fixtures.record('cdn.zone.example.com','192.0.2.8',30,'address')])
        ledger.observe_changes(event,0,1000)
        change=ledger.reconfigure_changes([Policy('one',('cdn.zone.example.com',))],3)
        self.assertEqual(change['tables_removed'],{'one':{'192.0.2.8'}})
        self.assertEqual(ledger.anchors,set());self.assertEqual(ledger.tables(3),{'one':set()})
        reply=fixtures.answer('cdn.zone.example.com',[fixtures.record('cdn.zone.example.com','192.0.2.8',25,'address')],5)
        ledger.observe_changes(reply,5,1005)
        self.assertEqual({l.deadline for l in ledger.leases.values()},{30})
        self.assertEqual(ledger.expire_changes(30)['tables_removed'],{'one':{'192.0.2.8'}})

    def test_policy_edit_failure_is_atomic_and_table_identity_cannot_change(self):
        ledger=IndexedProofLedger([Policy('one',('a.zone.example.com',))])
        ledger.observe_changes(fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',10,'same')]),0,1000)
        before=copy.deepcopy(ledger.__dict__)
        with self.assertRaises(ValueError):ledger.reconfigure_changes([Policy('other',('a.zone.example.com',))],1)
        self.assertEqual(ledger.policies,before['policies']);self.assertEqual(ledger.proofs,before['proofs'])
        self.assertEqual(ledger.leases,before['leases']);self.assertEqual(ledger.anchors,before['anchors'])
        # Changed matching order alone must not duplicate or renew memberships.
        delta=ledger.reconfigure_changes([Policy('one',('b.zone.example.com','a.zone.example.com'))],2)
        self.assertFalse(delta['tables_added']);self.assertFalse(delta['tables_removed'])
        self.assertEqual(ledger.leases,before['leases'])

    def pair(self):
        policies=[Policy('all',('*.zone.example.com',)),Policy('root',('a.zone.example.com','b.zone.example.com'))]
        return ProofLedger(policies),IndexedProofLedger(policies)

    def check_state(self,reference,indexed):
        self.assertEqual(indexed.proofs,reference.proofs)
        self.assertEqual(indexed.anchors,reference.anchors)
        self.assertEqual(indexed.leases,reference.leases)
        self.assertEqual(len(indexed._deadlines.heap),len(indexed.proofs))
        self.assertEqual(set(indexed._deadlines.positions),set(indexed.proofs))
        for i,entry in enumerate(indexed._deadlines.heap):
            self.assertEqual(indexed._deadlines.positions[entry[1]],i)
            if i:self.assertLessEqual(indexed._deadlines.heap[(i-1)//2],entry)
        members={p.name:set() for p in indexed.policies}
        for lease in indexed.leases.values():members[lease.policy].add(lease.address)
        self.assertEqual({name:set(rows) for name,rows in indexed._members.items()},members)

    def replay(self,members,change):
        for name,addresses in change['tables_removed'].items():
            self.assertTrue(addresses<=members[name]);members[name]-=addresses
        for name,addresses in change['tables_added'].items():
            self.assertFalse(addresses&members[name]);members[name]|=addresses

    def test_mixed_refresh_expiry_and_cname_sequences_match_reference_and_deltas(self):
        reference,indexed=self.pair();rng=random.Random(7174);members={p.name:set() for p in indexed.policies}
        names=['a.zone.example.com','b.zone.example.com','c.zone.example.com','cdn.zone.example.com','edge.zone.example.com'];now=0
        for step in range(350):
            now+=rng.choice((0,0,.1,1,3))
            if rng.random()<.2:
                reference.expire(now);delta=indexed.expire_changes(now)
            else:
                query=rng.choice(names);target=rng.choice(names);kind='CNAME' if query!=target and rng.random()<.45 else 'A'
                ttl=rng.choice((0,1,4,20,90));generation='proof-'+str(rng.randrange(8))
                value=target if kind=='CNAME' else '192.0.2.'+str(rng.randrange(1,5))
                rows=[fixtures.record(query,value,ttl,generation,kind)]
                if kind=='CNAME' and rng.random()<.5:rows.append(fixtures.record(target,'2001:db8::'+str(rng.randrange(1,5)),ttl,'v6-'+generation,'AAAA'))
                event=fixtures.answer(query,rows,now)
                reference.observe(event,now,1000+now);delta=indexed.observe_changes(event,now,1000+now)
            self.check_state(reference,indexed);self.replay(members,delta)
            self.assertEqual(members,{name:set(rows) for name,rows in indexed._members.items()})

    def test_shared_address_removed_only_after_last_policy_specific_proof(self):
        ledger=IndexedProofLedger([Policy('combined',('a.zone.example.com','b.zone.example.com')),Policy('short',('a.zone.example.com',))])
        for name,ttl in (('a.zone.example.com',5),('b.zone.example.com',20)):
            ledger.observe_changes(fixtures.answer(name,[fixtures.record(name,'192.0.2.7',ttl,name)]),0,1000)
        change=ledger.expire_changes(5)
        self.assertEqual(change['tables_removed'],{'short':{'192.0.2.7'}})
        self.assertEqual(ledger.tables(19),{'combined':{'192.0.2.7'},'short':set()})
        self.assertEqual(ledger.expire_changes(20)['tables_removed'],{'combined':{'192.0.2.7'}})

    def test_shorter_cache_proof_updates_deadline_without_extra_heap_entries(self):
        reference,indexed=self.pair()
        for i in range(100):
            event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',200-i,'same')])
            reference.observe(event,0,1000);indexed.observe_changes(event,0,1000)
            self.check_state(reference,indexed)
        self.assertEqual(indexed._deadlines.next,101)
        self.assertFalse(indexed.expire_changes(100)['tables_removed'])
        self.assertEqual(indexed.expire_changes(101)['tables_removed'],{'all':{'192.0.2.1'},'root':{'192.0.2.1'}})

    def test_zero_ttl_duplicate_shortens_same_proof_in_any_record_order(self):
        for order in ((0,60),(60,0)):
            reference,indexed=self.pair()
            first=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',120,'same')])
            reference.observe(first,0,1000);indexed.observe_changes(first,0,1000)
            later=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',ttl,'same') for ttl in order],1)
            reference.observe(later,1,1001);change=indexed.observe_changes(later,1,1001)
            self.check_state(reference,indexed);self.assertTrue(change['tables_removed'])

    def test_repeated_cache_hits_do_not_rederive_or_scan_unrelated_proofs(self):
        ledger=IndexedProofLedger([Policy('all',('*.zone.example.com',))])
        event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',60,'same')])
        ledger.observe_changes(event,0,1000)
        ledger._walk=lambda *args:self.fail('unchanged cache hit need not derive any roots')
        self.assertEqual(ledger.observe_changes(event,0,1000)['affected_roots'],0)
        self.assertEqual(len(ledger._deadlines.heap),1)

    def test_direct_refresh_retains_older_lease_objects_and_shared_ip_counts(self):
        reference,indexed=self.pair();members={p.name:set() for p in indexed.policies}
        for name,ttl in (('a.zone.example.com',50),('b.zone.example.com',80)):
            event=fixtures.answer(name,[fixtures.record(name,'192.0.2.7',ttl,'first')])
            reference.observe(event,0,1000);self.replay(members,indexed.observe_changes(event,0,1000))
        older=dict(indexed.leases)
        event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.7',10,'second'),
            fixtures.record('a.zone.example.com','192.0.2.8',20,'second')],1)
        with patch.object(indexed,'_walk',side_effect=AssertionError('old direct leases must not be rebuilt')):
            change=indexed.observe_changes(event,1,1001)
        reference.observe(event,1,1001);self.check_state(reference,indexed);self.replay(members,change)
        for key,lease in older.items():self.assertIs(indexed.leases[key],lease)
        for policy in ('all','root'):self.assertEqual(indexed._members[policy]['192.0.2.7'],3)
        for now in (11,21,50,79,80):
            reference.expire(now);change=indexed.expire_changes(now)
            self.check_state(reference,indexed);self.replay(members,change)
        self.assertEqual(members,{'all':set(),'root':set()})

    def test_many_direct_generations_then_cname_transitions_match_reference(self):
        reference,indexed=self.pair();rng=random.Random(1820)
        members={p.name:set() for p in indexed.policies}
        for step in range(70):
            name='a.zone.example.com' if step%2 else 'b.zone.example.com';now=step/4
            rows=[fixtures.record(name,'192.0.2.'+str(i),rng.randrange(20,100),str(step)) for i in range(1,13)]
            event=fixtures.answer(name,rows,now)
            reference.observe(event,now,1000+now);self.replay(members,indexed.observe_changes(event,now,1000+now))
            self.check_state(reference,indexed)
        # A new edge to an already populated owner must see all retained generations.
        events=[fixtures.answer('c.zone.example.com',[fixtures.record('c.zone.example.com','a.zone.example.com',40,'edge','CNAME')],18),
                fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.99',30,'new')],19),
                fixtures.answer('b.zone.example.com',[fixtures.record('b.zone.example.com','cdn.zone.example.com',50,'edge','CNAME'),
                    fixtures.record('cdn.zone.example.com','2001:db8::7',40,'v6','AAAA')],20)]
        for now,event in zip((18,19,20),events):
            reference.observe(event,now,1000+now);self.replay(members,indexed.observe_changes(event,now,1000+now))
            self.check_state(reference,indexed)
        for now in range(21,121):
            reference.expire(now);self.replay(members,indexed.expire_changes(now));self.check_state(reference,indexed)

    def test_direct_capacity_failures_leave_proofs_leases_and_indexes_unchanged(self):
        for limit in ('max_proofs','max_leases','max_walk'):
            ledger=IndexedProofLedger([Policy('one',('a.zone.example.com',))])
            first=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.1',60,'first')])
            ledger.observe_changes(first,0,1000);setattr(ledger,limit,1)
            before=copy.deepcopy(ledger.__dict__)
            second=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','192.0.2.2',30,'second')],1)
            with self.assertRaises(OverflowError):ledger.observe_changes(second,1,1001)
            for key in ('proofs','anchors','leases','_owners','_parents','_roots','_root_leases','_members'):
                self.assertEqual(getattr(ledger,key),before[key])
            self.assertEqual(ledger._deadlines.heap,before['_deadlines'].heap)
            self.assertEqual(ledger._deadlines.positions,before['_deadlines'].positions)

    def test_direct_expiry_keeps_surviving_lease_objects_and_last_shared_mapping(self):
        reference,indexed=self.pair();members={p.name:set() for p in indexed.policies}
        for name,ttl,identity in (('a.zone.example.com',5,'short'),('a.zone.example.com',20,'long'),('b.zone.example.com',30,'other')):
            event=fixtures.answer(name,[fixtures.record(name,'192.0.2.7',ttl,identity)])
            reference.observe(event,0,1000);self.replay(members,indexed.observe_changes(event,0,1000))
        survivors={k:l for k,l in indexed.leases.items() if l.deadline>5}
        with patch.object(indexed,'_walk',side_effect=AssertionError('direct expiry must not rebuild surviving leases')):
            change=indexed.expire_changes(5)
        reference.expire(5);self.check_state(reference,indexed);self.replay(members,change)
        self.assertEqual(change['leases_upserted'],());self.assertFalse(change['tables_removed'])
        for k,l in survivors.items():self.assertIs(indexed.leases[k],l)
        for now in (20,30):
            reference.expire(now);change=indexed.expire_changes(now);self.check_state(reference,indexed);self.replay(members,change)
        self.assertFalse(indexed.anchors);self.assertFalse(indexed._root_leases)

    def test_direct_expiry_and_same_key_replacement_are_atomic_and_match_reference(self):
        reference,indexed=self.pair();members={p.name:set() for p in indexed.policies};rng=random.Random(181)
        for step in range(300):
            now=step/2;name=rng.choice(('a.zone.example.com','b.zone.example.com','c.zone.example.com','unmatched.other.example.com'))
            event=fixtures.answer(name,[fixtures.record(name,'192.0.2.'+str(rng.randrange(1,4)),rng.randrange(0,8),'generation-'+str(rng.randrange(3)))],now)
            reference.observe(event,now,1000+now);change=indexed.observe_changes(event,now,1000+now)
            self.check_state(reference,indexed);self.replay(members,change)
            if step%7==0:
                reference.expire(now+.1);change=indexed.expire_changes(now+.1);self.check_state(reference,indexed);self.replay(members,change)
        reference.expire(200);self.replay(members,indexed.expire_changes(200));self.check_state(reference,indexed)

    def test_unmatched_direct_proofs_remain_available_to_later_cname_query(self):
        policies=[Policy('one',('a.zone.example.com',))];reference=ProofLedger(policies);indexed=IndexedProofLedger(policies)
        for now in (0,1,2):
            event=fixtures.answer('cdn.zone.example.com',[fixtures.record('cdn.zone.example.com','192.0.2.7',30,str(now))],now)
            reference.observe(event,now,1000+now);change=indexed.observe_changes(event,now,1000+now)
            self.assertFalse(change['tables_added']);self.check_state(reference,indexed)
        event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','cdn.zone.example.com',60,'edge','CNAME')],3)
        reference.observe(event,3,1003);indexed.observe_changes(event,3,1003);self.check_state(reference,indexed)
        self.assertEqual(len(indexed.leases),3)

    def test_new_owner_recalculates_only_its_related_roots(self):
        ledger=IndexedProofLedger([Policy('all',('*.zone.example.com',))])
        for i in range(60):
            name=f'n{i}.zone.example.com';ledger.observe_changes(fixtures.answer(name,[fixtures.record(name,'192.0.2.1',60,'same')]),0,1000)
        change=ledger.observe_changes(fixtures.answer('n5.zone.example.com',[fixtures.record('n5.zone.example.com','192.0.2.2',30,'new')]),0,1000)
        self.assertEqual(change['affected_roots'],1);self.assertEqual(change['tables_added'],{'all':{'192.0.2.2'}})
        self.assertFalse(change['tables_removed'])

    def test_proof_and_derived_capacity_failure_preserve_all_indexes_even_with_due_expiry(self):
        for limit in ('max_proofs','max_leases'):
            ledger=IndexedProofLedger([Policy('all',('*.zone.example.com',))])
            for i,ttl in ((1,1),(2,60)):
                name=f'n{i}.zone.example.com';ledger.observe_changes(fixtures.answer(name,[fixtures.record(name,'192.0.2.1',ttl,'same')]),0,1000)
            before=copy.deepcopy(ledger.__dict__);setattr(ledger,limit,1)
            event=fixtures.answer('n3.zone.example.com',[fixtures.record('n3.zone.example.com','192.0.2.2',60,'new')],2)
            with self.assertRaises(OverflowError):ledger.observe_changes(event,2,1002)
            after=ledger.__dict__;after[limit]=before[limit]
            for key in ('proofs','anchors','leases','_owners','_parents','_roots','_root_leases','_members'):self.assertEqual(after[key],before[key])
            self.assertEqual(after['_deadlines'].heap,before['_deadlines'].heap)
            self.assertEqual(after['_deadlines'].positions,before['_deadlines'].positions)

    def test_restore_rebuilds_indexes_then_canonical_refresh_and_expiry_match(self):
        reference,indexed=self.pair()
        event=fixtures.answer('a.zone.example.com',[fixtures.record('a.zone.example.com','cdn.zone.example.com',60,'edge','CNAME'),fixtures.record('cdn.zone.example.com','192.0.2.1',10,'ip')])
        reference.observe(event,0,1000);snapshot=reference.snapshot(0,1000)
        indexed.restore(snapshot,0,1020,True);reference.restore(snapshot,0,1020,True)
        event=fixtures.answer('cdn.zone.example.com',[fixtures.record('cdn.zone.example.com','192.0.2.2',90,'new')],25)
        indexed.observe_changes(event,5,1025);reference.observe(event,5,1025);self.check_state(reference,indexed)
        indexed.expire_changes(40);reference.expire(40);self.check_state(reference,indexed)


class DeadlineIndexTests(unittest.TestCase):
    def test_sparse_and_dense_bulk_removal_preserve_heap_and_positions(self):
        rng=random.Random(1811)
        for count in (1,31,32,90,300):
            index=_Deadlines();reference={}
            for i in range(300):
                key=('n','A','192.0.2.1',str(i));deadline=rng.randrange(1000)
                index.set(key,deadline);reference[key]=deadline
            removed=set(rng.sample(list(reference),count));index.remove_many(removed)
            for key in removed:reference.pop(key)
            self.assertEqual(index.due(1000),set(reference));self.assertEqual(len(index.heap),len(reference))
            self.assertEqual(index.next,min(reference.values()) if reference else None)
            for i,(deadline,key) in enumerate(index.heap):
                self.assertEqual(index.positions[key],i);self.assertEqual(deadline,reference[key])
                if i:self.assertLessEqual(index.heap[(i-1)//2],index.heap[i])
            before=(list(index.heap),dict(index.positions))
            with self.assertRaises(KeyError):index.remove_many({('missing',)})
            self.assertEqual((index.heap,index.positions),before)

    def test_arbitrary_update_remove_order_and_due_preview(self):
        rng=random.Random(65);index=_Deadlines();reference={}
        for step in range(1000):
            key=('name','A','192.0.2.1',str(rng.randrange(100)))
            if key in reference and rng.random()<.3:index.remove(key);del reference[key]
            else:
                deadline=rng.randrange(200);index.set(key,deadline);reference[key]=deadline
            now=rng.randrange(200);before=list(index.heap)
            self.assertEqual(index.due(now),{key for key,value in reference.items() if value<=now})
            self.assertEqual(index.heap,before)
            self.assertEqual(index.next,min(reference.values()) if reference else None)
            self.assertEqual(len(index.heap),len(reference))
            for i,entry in enumerate(index.heap):
                self.assertEqual(index.positions[entry[1]],i)
                if i:self.assertLessEqual(index.heap[(i-1)//2],entry)
