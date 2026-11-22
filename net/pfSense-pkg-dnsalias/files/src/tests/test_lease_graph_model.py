"""Independent membership oracle: propagate address deadlines BACK to queries.

The production ledger walks forward CNAME paths and maintains proof indexes.
This model shares no parser, matching, traversal, deadline or delta code. It
collapses reverse reachability using the best surviving path per owner. These
are normalized-answer component tests, not Unbound adapter or PF qualification.
"""
from collections import defaultdict
import ipaddress
import random
import unittest

from dnsalias.indexedproofs import IndexedProofLedger
from dnsalias.leases import Policy


POLICIES={'apps':('*.apps.other.example.com',),'one':('a0.apps.other.example.com',),
          'cdn':('*.cdn.other.example.com',),'unqueried':('unused.other.example.com',)}


def matches(name,patterns):
    return any(name==p if not p.startswith('*.') else name.endswith(p[1:]) for p in patterns)


def message(query,rows,now,delay=0):
    return {'qname':query,'records':rows,'observed_utc':1000+now-delay,
            'trusted':True,'ttl_basis':'remaining','stale':False,'rcode':'NOERROR'}


def record(owner,kind,value,ttl,generation):
    return {'name':owner,'type':kind,'value':value,'remaining_ttl':ttl,'proof_id':generation}


class ReverseModel:
    def __init__(self):
        self.proofs={};self.anchors=set();self.policies=dict(POLICIES)

    def expire(self,now):
        self.proofs={key:end for key,end in self.proofs.items() if end>now}
        owners={key[0] for key in self.proofs}
        self.anchors={root for root in self.anchors if root[1] in owners}

    def observe(self,event,now):
        # A reply can arrive before the expiry manager's next tick. Remove old
        # proof lifetimes here while retaining queried roots until the atomic
        # answer update is complete; an explicit earlier tick retires roots.
        self.proofs={key:end for key,end in self.proofs.items() if end>now}
        query=event['qname'].lower().rstrip('.')
        edges={r['name'].lower().rstrip('.'):r['value'].lower().rstrip('.')
               for r in event['records'] if r['type']=='CNAME'}
        reachable={query};node=query
        while node in edges:
            node=edges[node]
            if node in reachable:raise AssertionError('test generator must produce acyclic answers')
            reachable.add(node)
        for row in event['records']:
            owner=row['name'].lower().rstrip('.')
            if owner not in reachable:continue
            kind=row['type']
            value=row['value'].lower().rstrip('.') if kind=='CNAME' else str(ipaddress.ip_address(row['value']))
            key=(owner,kind,value,row['proof_id'])
            end=event['observed_utc']-1000+row['remaining_ttl']
            self.proofs[key]=min(self.proofs.get(key,end),end)
        self.anchors.update((p,query) for p,patterns in self.policies.items() if matches(query,patterns))
        self.expire(now)

    def reconfigure(self,patterns,now):
        self.expire(now);self.policies=dict(patterns)
        self.anchors={(policy,root) for policy,root in self.anchors
                      if policy in self.policies and matches(root,self.policies[policy])}

    def tables(self):
        parents=defaultdict(list);addresses=[]
        for (owner,kind,value,_),end in self.proofs.items():
            if kind=='CNAME':parents[value].append((owner,end))
            else:addresses.append((owner,value,end))
        tables={p:set() for p in self.policies}
        for owner,address,deadline in addresses:
            # Best bottleneck deadline at each upstream name, independent of
            # how many proof generations/paths lead to the same destination.
            best={owner:deadline};pending=[owner]
            while pending:
                child=pending.pop()
                for parent,edge_end in parents[child]:
                    end=min(best[child],edge_end)
                    if end>best.get(parent,float('-inf')):
                        best[parent]=end;pending.append(parent)
            for policy,root in self.anchors:
                if root in best:tables[policy].add(address)
        return tables


class IndependentLeaseGraphTests(unittest.TestCase):
    def pair(self):
        return IndexedProofLedger([Policy(p,names) for p,names in POLICIES.items()]),ReverseModel(),{p:set() for p in POLICIES}

    def replay(self,actual,delta):
        for policy,addresses in delta['tables_removed'].items():
            self.assertTrue(addresses<=actual[policy]);actual[policy]-=addresses
        for policy,addresses in delta['tables_added'].items():
            self.assertFalse(addresses&actual[policy]);actual[policy]|=addresses

    def step(self,pair,now,event=None,*,expire_first=True):
        ledger,model,actual=pair
        if event is None or expire_first:
            self.replay(actual,ledger.expire_changes(now));model.expire(now)
        if event is not None:
            self.replay(actual,ledger.observe_changes(event,now,1000+now));model.observe(event,now)
        expected=model.tables()
        self.assertEqual(actual,expected)
        self.assertEqual(ledger.tables(now),expected)
        return expected

    def reconfigure(self,pair,now,patterns):
        ledger,model,actual=pair
        self.replay(actual,ledger.reconfigure_changes([Policy(p,names) for p,names in patterns.items()],now))
        model.reconfigure(patterns,now);expected=model.tables()
        self.assertEqual(actual,expected);self.assertEqual(ledger.tables(now),expected)
        return expected

    def replace_policies(self,pair,now,patterns):
        ledger,model,actual=pair
        for policy in patterns:actual.setdefault(policy,set())
        self.replay(actual,ledger.replace_policy_set([Policy(p,names) for p,names in patterns.items()],now))
        for policy in set(actual)-set(patterns):
            self.assertFalse(actual.pop(policy))
        model.reconfigure(patterns,now);expected=model.tables()
        self.assertEqual(actual,expected);self.assertEqual(ledger.tables(now),expected)
        return expected

    def test_shared_ip_keeps_only_each_alias_final_valid_path(self):
        pair=self.pair()
        self.step(pair,0,message('a0.apps.other.example.com',[
            record('a0.apps.other.example.com','CNAME','edge.cdn.other.example.com',12,'edge-a'),
            record('edge.cdn.other.example.com','CNAME','origin.cdn.other.example.com',50,'edge-b'),
            record('origin.cdn.other.example.com','A','192.0.2.7',100,'addr')],0))
        self.step(pair,1,message('a1.apps.other.example.com',[record('a1.apps.other.example.com','A','192.0.2.7',29,'direct')],1))
        # A query of the canonical owner refreshes addresses, not earlier CNAME TTLs.
        self.step(pair,5,message('origin.cdn.other.example.com',[
            record('origin.cdn.other.example.com','A','192.0.2.8',40,'new-addr')],5))
        result=self.step(pair,12)
        self.assertEqual(result,{'apps':{'192.0.2.7'},'one':set(),'cdn':{'192.0.2.7','192.0.2.8'},'unqueried':set()})
        self.assertFalse(self.step(pair,30)['apps'])
        self.assertEqual(self.step(pair,45)['cdn'],{'192.0.2.7'})
        self.assertTrue(all(not ips for ips in self.step(pair,100).values()))

    def test_retained_cycle_and_unrelated_additional_record_do_not_widen_tables(self):
        pair=self.pair()
        self.step(pair,0,message('a0.apps.other.example.com',[
            record('a0.apps.other.example.com','CNAME','edge.cdn.other.example.com',40,'old-edge'),
            record('edge.cdn.other.example.com','A','192.0.2.7',40,'old-address')],0))
        # Separate valid generations can form a cycle in retained evidence.
        self.step(pair,1,message('edge.cdn.other.example.com',[
            record('edge.cdn.other.example.com','CNAME','a0.apps.other.example.com',40,'new-edge'),
            record('a0.apps.other.example.com','AAAA','2001:db8::8',40,'new-address')],1),expire_first=False)
        result=self.step(pair,2,message('origin0.cdn.other.example.com',[
            record('origin0.cdn.other.example.com','A','192.0.2.11',30,'direct'),
            record('edge.cdn.other.example.com','A','198.51.100.250',120,'unrelated')],2))
        self.assertEqual(result['one'],{'192.0.2.7','2001:db8::8'})
        self.assertNotIn('198.51.100.250',set().union(*result.values()))
        self.assertEqual(self.step(pair,40)['one'],{'2001:db8::8'})
        self.assertTrue(all(not ips for ips in self.step(pair,41).values()))

    def test_name_edits_do_not_borrow_another_tables_history_or_extend_shared_ip(self):
        pair=self.pair()
        self.step(pair,0,message('a0.apps.other.example.com',[record('a0.apps.other.example.com','A','192.0.2.7',60,'a')],0))
        self.step(pair,0,message('a1.apps.other.example.com',[record('a1.apps.other.example.com','A','192.0.2.7',90,'b')],0))
        patterns=POLICIES|{'one':('a1.apps.other.example.com',)}
        result=self.reconfigure(pair,10,patterns)
        self.assertEqual(result['apps'],{'192.0.2.7'});self.assertFalse(result['one'])
        self.assertEqual(self.step(pair,11,message('a1.apps.other.example.com',[
            record('a1.apps.other.example.com','A','192.0.2.7',79,'b')],11))['one'],{'192.0.2.7'})
        patterns=patterns|{'apps':('a0.apps.other.example.com',)}
        self.reconfigure(pair,12,patterns)
        result=self.step(pair,60)
        self.assertFalse(result['apps']);self.assertEqual(result['one'],{'192.0.2.7'})
        self.assertTrue(all(not ips for ips in self.reconfigure(pair,65,patterns|{'one':('never.other.example.com',)}).values()))

    def test_recreated_alias_waits_for_own_reply_and_keeps_shared_path_deadlines(self):
        pair=self.pair()
        self.step(pair,0,message('a0.apps.other.example.com',[
            record('a0.apps.other.example.com','CNAME','edge.cdn.other.example.com',30,'root-edge'),
            record('edge.cdn.other.example.com','A','192.0.2.7',100,'shared-v4')],0))
        self.step(pair,1,message('a1.apps.other.example.com',[
            record('a1.apps.other.example.com','A','192.0.2.7',79,'independent-v4')],1))
        self.step(pair,2,message('edge.cdn.other.example.com',[
            record('edge.cdn.other.example.com','A','192.0.2.7',98,'shared-v4'),
            record('edge.cdn.other.example.com','AAAA','2001:db8::8',38,'shared-v6')],2))
        # Retire one identity while the other tables retain the same CNAME
        # graph and addresses. Reusing its name must not resurrect old roots.
        without_one={p:names for p,names in POLICIES.items() if p!='one'}
        result=self.replace_policies(pair,5,without_one)
        self.assertEqual(result['apps'],{'192.0.2.7','2001:db8::8'})
        self.assertEqual(result['cdn'],result['apps'])
        self.assertFalse(self.replace_policies(pair,6,POLICIES)['one'])
        result=self.step(pair,7,message('edge.cdn.other.example.com',[
            record('edge.cdn.other.example.com','A','192.0.2.7',93,'shared-v4')],7))
        self.assertFalse(result['one']) # A canonical-owner reply is not a query of a0.
        result=self.step(pair,8,message('a0.apps.other.example.com',[
            record('a0.apps.other.example.com','CNAME','edge.cdn.other.example.com',22,'root-edge'),
            record('edge.cdn.other.example.com','A','192.0.2.7',92,'shared-v4'),
            record('edge.cdn.other.example.com','AAAA','2001:db8::8',32,'shared-v6')],8))
        self.assertEqual(result['one'],{'192.0.2.7','2001:db8::8'})
        result=self.step(pair,30)
        self.assertFalse(result['one'])
        self.assertEqual(result['apps'],{'192.0.2.7'})
        self.assertEqual(result['cdn'],{'192.0.2.7','2001:db8::8'})
        self.assertEqual(self.step(pair,40)['cdn'],{'192.0.2.7'})
        result=self.step(pair,80)
        self.assertFalse(result['apps']);self.assertEqual(result['cdn'],{'192.0.2.7'})
        self.assertTrue(all(not ips for ips in self.step(pair,100).values()))

    def test_bounded_seeded_reply_rotation_cache_delivery_and_expiry(self):
        for seed in (7,19,2026,7174):
            with self.subTest(seed=seed):
                rng=random.Random(seed);pair=self.pair();now=0;cached=[];patterns=dict(POLICIES)
                roots=['a'+str(i)+'.apps.other.example.com' for i in range(4)]
                mids=['edge'+str(i)+'.cdn.other.example.com' for i in range(3)]
                leaves=['origin'+str(i)+'.cdn.other.example.com' for i in range(3)]
                for index in range(180):
                    now+=rng.choice((0,.25,1,3))
                    if rng.random()<.18:
                        self.step(pair,now);continue
                    if rng.random()<.12:
                        patterns=patterns|{'one':rng.choice((('a0.apps.other.example.com',),('a1.apps.other.example.com',),('*.apps.other.example.com',),('never.other.example.com',))),
                            'cdn':rng.choice((('*.cdn.other.example.com',),('origin0.cdn.other.example.com',),('never.other.example.com',)))}
                        self.reconfigure(pair,now,patterns);continue
                    if cached and rng.random()<.25:
                        query,old,observed=cached[rng.randrange(len(cached))]
                        rows=[dict(row,remaining_ttl=max(0,int(observed+row['remaining_ttl']-now))) for row in old]
                        event=message(query,rows,now)
                    else:
                        query=rng.choice(roots+mids+leaves);path=[query]
                        if query in roots and rng.random()<.75:path.append(rng.choice(mids))
                        if path[-1] in mids and rng.random()<.8:path.append(rng.choice(leaves))
                        rows=[]
                        for i,(owner,target) in enumerate(zip(path,path[1:])):
                            rows.append(record(owner,'CNAME',target,rng.choice((0,2,9,40,90)),f'e-{index}-{i}'))
                        kind=rng.choice(('A','AAAA'));address=('192.0.2.' if kind=='A' else '2001:db8::')+str(rng.randrange(1,5))
                        rows.append(record(path[-1],kind,address,rng.choice((0,1,7,20,80)),f'a-{index}'))
                        if rng.random()<.25:
                            other=('192.0.2.' if kind=='A' else '2001:db8::')+str(rng.randrange(1,5))
                            rows.append(record(path[-1],kind,other,rng.choice((0,1,9,60)),f'a-{index}'))
                        if rng.random()<.35:
                            # An unrelated additional RR must not refresh a leaf
                            # merely because an earlier valid path points to it.
                            outside=next(name for name in leaves if name not in path)
                            rows.append(record(outside,'A','198.51.100.250',120,f'ignored-{index}'))
                        delay=rng.choice((0,0,.25,2));event=message(query,rows,now,delay)
                        cached.append((query,rows,now-delay))
                    self.step(pair,now,event,expire_first=rng.choice((True,False)))
                self.assertTrue(all(not ips for ips in self.step(pair,now+1000).values()))


if __name__=='__main__':unittest.main()
