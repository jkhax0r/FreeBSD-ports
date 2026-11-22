import copy
import unittest

from dnsalias.leases import Policy
from dnsalias.proofs import ProofLedger
from dnsalias.replynormalize import UnqualifiedReply, cname


def record(name, value, ttl, identity, kind="A"):
    return {"name":name,"type":kind,"value":value,"remaining_ttl":ttl,"proof_id":identity}


def answer(query, records, now=0):
    return {"qname":query,"records":records,"observed_utc":1000+now,
            "trusted":True,"ttl_basis":"remaining","stale":False,"rcode":"NOERROR"}


class ProofTests(unittest.TestCase):
    def test_cname_wire_labels_keep_their_boundaries(self):
        self.assertEqual(cname(b'\x03www\x07example\x03com\x00'), 'www.example.com')
        with self.assertRaises(UnqualifiedReply):
            cname(b'\x0bwww.example\x03com\x00')

    def setUp(self):
        self.ledger = ProofLedger([Policy("media", ("a.zone.example.com", "b.zone.example.com")),
                                   Policy("other", ("b.zone.example.com",))])

    def observe(self, query, records, now=0):
        return self.ledger.observe(answer(query, records, now), now, 1000+now)

    def cname(self, edge_ttl=120, address_ttl=20):
        self.observe("a.zone.example.com", [record("a.zone.example.com", "cdn.zone.example.com", edge_ttl, "edge-1", "CNAME"),
                                   record("cdn.zone.example.com", "192.0.2.1", address_ttl, "addr-1")])

    def test_canonical_refresh_reuses_live_edge_after_old_address_expires(self):
        self.cname()
        self.assertFalse(self.ledger.tables(25)["media"])
        self.observe("cdn.zone.example.com", [record("cdn.zone.example.com", "192.0.2.2", 60, "addr-2")], 30)
        self.assertEqual(self.ledger.tables(89)["media"], {"192.0.2.2"})
        self.assertFalse(self.ledger.tables(90)["media"])
        self.assertFalse(self.ledger.tables(90)["other"])

    def test_canonical_refresh_never_extends_earlier_cname(self):
        self.cname(edge_ttl=20, address_ttl=120)
        self.observe("cdn.zone.example.com", [record("cdn.zone.example.com", "192.0.2.2", 80, "addr-2")], 10)
        self.assertEqual(self.ledger.tables(19)["media"], {"192.0.2.1", "192.0.2.2"})
        self.assertFalse(self.ledger.tables(20)["media"])
        self.observe("cdn.zone.example.com", [record("cdn.zone.example.com", "192.0.2.3", 80, "addr-3")], 30)
        self.assertFalse(self.ledger.tables(30)["media"])

    def test_cache_ids_cannot_extend_any_proof(self):
        self.cname(edge_ttl=60, address_ttl=60)
        self.observe("a.zone.example.com", [record("a.zone.example.com", "cdn.zone.example.com", 60, "edge-1", "CNAME"),
                                   record("cdn.zone.example.com", "192.0.2.1", 60, "addr-1")], 10)
        self.assertTrue(self.ledger.tables(59)["media"])
        self.assertFalse(self.ledger.tables(60)["media"])

    def test_independent_name_justifies_shared_ip_after_first_expires(self):
        self.cname(edge_ttl=20, address_ttl=120)
        self.observe("b.zone.example.com", [record("b.zone.example.com", "192.0.2.1", 80, "b-1")])
        self.assertEqual(self.ledger.tables(40), {"media":{"192.0.2.1"}, "other":{"192.0.2.1"}})
        self.assertFalse(self.ledger.tables(80)["media"])

    def test_shared_ip_deadline_is_independent_in_each_policy_table(self):
        ledger=ProofLedger([Policy('short',('a.zone.example.com',)),Policy('long',('b.zone.example.com',))])
        ledger.observe(answer('a.zone.example.com',[record('a.zone.example.com','192.0.2.7',20,'a1')]),0,1000)
        ledger.observe(answer('b.zone.example.com',[record('b.zone.example.com','192.0.2.7',80,'b1')]),0,1000)
        self.assertEqual(ledger.tables(20),{'short':set(),'long':{'192.0.2.7'}})
        self.assertEqual(ledger.tables(80),{'short':set(),'long':set()})

    def test_rotating_one_name_cannot_remove_another_names_live_shared_ip(self):
        self.observe('a.zone.example.com',[record('a.zone.example.com','192.0.2.7',20,'a1')])
        self.observe('b.zone.example.com',[record('b.zone.example.com','192.0.2.7',80,'b1')])
        self.observe('a.zone.example.com',[record('a.zone.example.com','192.0.2.8',20,'a2')],10)
        self.assertEqual(self.ledger.tables(25)['media'],{'192.0.2.7','192.0.2.8'})
        self.assertEqual(self.ledger.tables(30)['media'],{'192.0.2.7'})
        # An otherwise trusted adapter repeating a full TTL under the same
        # generation cannot move the already-known original deadline.
        self.observe('b.zone.example.com',[record('b.zone.example.com','192.0.2.7',80,'b1')],50)
        self.assertEqual(self.ledger.tables(79)['media'],{'192.0.2.7'})
        self.assertFalse(self.ledger.tables(80)['media'])

    def test_rotating_cname_preserves_both_unexpired_paths(self):
        self.cname(edge_ttl=80, address_ttl=80)
        self.observe("a.zone.example.com", [record("a.zone.example.com", "new.zone.example.com", 40, "edge-2", "CNAME"),
                                   record("new.zone.example.com", "192.0.2.2", 100, "new-1")], 10)
        self.observe("cdn.zone.example.com", [record("cdn.zone.example.com", "192.0.2.3", 100, "old-2")], 20)
        self.assertEqual(self.ledger.tables(30)["media"], {"192.0.2.1", "192.0.2.2", "192.0.2.3"})
        self.assertEqual(self.ledger.tables(50)["media"], {"192.0.2.1", "192.0.2.3"})
        self.assertFalse(self.ledger.tables(80)["media"])

    def test_multihop_edge_refresh_independent_of_outer_edge(self):
        self.observe("a.zone.example.com", [record("a.zone.example.com", "mid.zone.example.com", 100, "outer", "CNAME"),
                                   record("mid.zone.example.com", "cdn.zone.example.com", 10, "inner", "CNAME"),
                                   record("cdn.zone.example.com", "192.0.2.1", 100, "ip")])
        self.assertFalse(self.ledger.tables(15)["media"])
        self.observe("mid.zone.example.com", [record("mid.zone.example.com", "cdn.zone.example.com", 30, "inner-new", "CNAME")], 20)
        self.assertEqual(self.ledger.tables(49)["media"], {"192.0.2.1"})
        self.assertFalse(self.ledger.tables(50)["media"])

    def test_unrelated_records_cannot_seed_alias_or_later_chain(self):
        self.observe("outside.zone.example.com", [record("outside.zone.example.com", "192.0.2.10", 60, "outside"),
                                         record("b.zone.example.com", "192.0.2.20", 60, "injected")])
        self.assertFalse(self.ledger.tables(1)["media"])
        self.observe("a.zone.example.com", [record("a.zone.example.com", "b.zone.example.com", 50, "edge", "CNAME")], 2)
        self.assertFalse(self.ledger.tables(2)["media"])
        self.assertFalse(any(p.name == "b.zone.example.com" for p in self.ledger.proofs.values()))

    def test_all_45_addresses_and_ipv6_survive_without_wire_subset(self):
        rows = [record("a.zone.example.com", f"192.0.2.{i}", 60, "rrset-a") for i in range(1, 46)]
        rows.append(record("a.zone.example.com", "2001:db8::1", 30, "rrset-aaaa", "AAAA"))
        self.observe("a.zone.example.com", rows)
        self.assertEqual(len(self.ledger.tables(1)["media"]), 46)
        self.assertEqual(len(self.ledger.tables(30)["media"]), 45)

    def test_malformed_and_overbudget_inputs_leave_existing_state_intact(self):
        self.cname()
        before = self.ledger.snapshot(0, 1000)
        with self.assertRaises(ValueError):
            self.observe("b.zone.example.com", [record("b.zone.example.com", "bad-address", 60, "bad")])
        self.ledger.max_walk = 1
        with self.assertRaises(OverflowError):
            self.observe("b.zone.example.com", [record("b.zone.example.com", "192.0.2.3", 60, "valid")])
        self.ledger.max_walk = 100000
        self.assertEqual(self.ledger.snapshot(0, 1000), before)

    def test_stale_negative_zero_and_sinkhole(self):
        self.cname()
        negative = answer("a.zone.example.com", [], 10) | {"rcode":"NXDOMAIN"}
        self.ledger.observe(negative, 10, 1010)
        self.assertTrue(self.ledger.tables(10)["media"])
        with self.assertRaises(ValueError):
            self.ledger.observe(negative | {"stale":True}, 10, 1010)
        self.observe("b.zone.example.com", [record("b.zone.example.com", "0.0.0.0", 60, "sink"),
                                   record("b.zone.example.com", "192.0.2.2", 0, "zero")])
        self.assertFalse(self.ledger.tables(10)["other"])

    def test_clock_safe_restart_preserves_edges_for_future_canonical_refresh(self):
        self.cname()
        snapshot = self.ledger.snapshot(10, 1010)
        restored = ProofLedger(self.ledger.policies)
        with self.assertRaises(ValueError): restored.restore(snapshot, 0, 1025)
        with self.assertRaises(ValueError): restored.restore(snapshot, 0, 900, True)
        restored.restore(snapshot, 0, 1025, True)
        self.assertFalse(restored.tables(0)["media"])
        restored.observe(answer("cdn.zone.example.com", [record("cdn.zone.example.com", "192.0.2.2", 200, "new")], 30), 5, 1030)
        self.assertTrue(restored.tables(94)["media"])
        self.assertFalse(restored.tables(95)["media"])

    def test_restore_rejects_bad_clock_and_tampered_proofs_atomically(self):
        self.cname()
        snapshot = self.ledger.snapshot(0, 1000)
        for replacement in (float("nan"), float("inf"), True):
            with self.assertRaises(ValueError): self.ledger.restore(snapshot, 0, replacement, True)
        changed = copy.deepcopy(snapshot)
        changed["proofs"][0]["expires_utc"] = 999999999
        with self.assertRaises(ValueError): self.ledger.restore(changed, 0, 1000, True)
        self.assertEqual(self.ledger.snapshot(0, 1000), snapshot)
        changed = copy.deepcopy(snapshot)
        changed["proofs"].append(changed["proofs"][0])
        with self.assertRaises(ValueError): self.ledger.restore(changed, 0, 1000, True)

    def test_removed_policy_stays_removed_after_restart(self):
        self.cname()
        restored = ProofLedger([Policy("other", ("b.zone.example.com",))])
        restored.restore(self.ledger.snapshot(0, 1000), 0, 1001, True)
        self.assertEqual(restored.tables(0), {"other":set()})

    def test_loop_and_conflicting_single_answer_rejected(self):
        for rows in ([record("a.zone.example.com", "a.zone.example.com", 60, "loop", "CNAME")],
                     [record("a.zone.example.com", "one.zone.example.com", 60, "one", "CNAME"),
                      record("a.zone.example.com", "two.zone.example.com", 60, "two", "CNAME")]):
            with self.assertRaises(ValueError): self.observe("a.zone.example.com", rows)
        self.assertFalse(self.ledger.proofs)


if __name__ == "__main__":
    unittest.main()
