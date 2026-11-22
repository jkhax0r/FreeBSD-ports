import copy
import unittest
from dnsalias.leases import LeaseEngine, Policy


def event(name="a.zone.example.com", address="192.0.2.1", ttl=60, answer="one", observed=1000):
    return {"trusted":True, "ttl_basis":"remaining", "stale":False,
            "qname":name, "answer_id":answer, "observed_utc":observed, "rcode":"NOERROR",
            "records":[{"name":name,"type":"A","value":address,"remaining_ttl":ttl}]}


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.engine = LeaseEngine([Policy("work", ("*.zone.example.com",)), Policy("other", ("b.zone.example.com",))])

    def test_cache_hits_do_not_reset_full_ttl(self):
        self.engine.observe(event(), 0, 1000)
        self.engine.observe(event(ttl=50, observed=1010), 10, 1010)
        self.assertEqual(self.engine.tables(59)["work"], {"192.0.2.1"})
        self.assertEqual(self.engine.tables(60)["work"], set())

    def test_even_incorrect_repeated_generation_cannot_extend(self):
        self.engine.observe(event(), 0, 1000)
        self.engine.observe(event(ttl=60, observed=1010), 10, 1010)
        self.assertFalse(self.engine.tables(60)["work"])

    def test_rotation_preserves_old_address(self):
        self.engine.observe(event(), 0, 1000)
        self.engine.observe(event(address="192.0.2.2", answer="two", observed=1020), 20, 1020)
        self.assertEqual(self.engine.tables(30)["work"], {"192.0.2.1","192.0.2.2"})
        self.assertEqual(self.engine.tables(60)["work"], {"192.0.2.2"})
        self.assertFalse(self.engine.tables(80)["work"])

    def test_independent_names_and_policy_isolation(self):
        self.engine.observe(event(), 0, 1000)
        self.engine.observe(event(name="b.zone.example.com", ttl=120), 0, 1000)
        self.assertEqual(len(self.engine.leases), 3)
        self.assertEqual(self.engine.tables(90)["work"], {"192.0.2.1"})
        self.assertEqual(self.engine.tables(90)["other"], {"192.0.2.1"})
        self.assertFalse(self.engine.tables(120)["work"])

    def test_negative_answer_does_not_remove_prior_positive(self):
        self.engine.observe(event(), 0, 1000)
        e = event(); e["rcode"] = "NXDOMAIN"
        self.engine.observe(e, 10, 1010)
        self.assertTrue(self.engine.tables(20)["work"])

    def test_cname_minimum_ttl_and_unrelated_additional_ignored(self):
        e = event()
        e["records"] = [
            {"name":"a.zone.example.com","type":"CNAME","value":"cdn.other.example.com","remaining_ttl":20},
            {"name":"cdn.other.example.com","type":"A","value":"192.0.2.2","remaining_ttl":100},
            {"name":"unrelated.zone.example.com","type":"A","value":"192.0.2.3","remaining_ttl":100}]
        self.engine.observe(e, 0, 1000)
        self.assertEqual(self.engine.tables(19)["work"], {"192.0.2.2"})
        self.assertFalse(self.engine.tables(20)["work"])

    def test_ipv6_and_all_45_records(self):
        e = event()
        e["records"] = [{"name":"a.zone.example.com","type":"A","value":f"192.0.2.{i}","remaining_ttl":60} for i in range(1,46)]
        e["records"].append({"name":"a.zone.example.com","type":"AAAA","value":"2001:db8::1","remaining_ttl":60})
        self.engine.observe(e, 0, 1000)
        self.assertEqual(len(self.engine.tables(1)["work"]), 46)

    def test_untrusted_stale_or_unknown_ttl_rejected(self):
        for field,value in [("trusted",False),("stale",True),("ttl_basis","raw_swig")]:
            e = event(); e[field] = value
            with self.assertRaises(ValueError): self.engine.observe(e,0,1000)
        self.assertFalse(self.engine.leases)

    def test_zero_ttl_and_sinkhole_not_admitted(self):
        for addr,ttl in [("192.0.2.1",0),("0.0.0.0",60),("127.0.0.1",60)]:
            self.engine.observe(event(address=addr,ttl=ttl),0,1000)
        self.assertFalse(self.engine.leases)

    def test_suffix_is_dns_label_boundary(self):
        p = Policy("work", ("*.zone.example.com",))
        self.assertTrue(p.matches("A.ZONE.EXAMPLE.COM."))
        self.assertFalse(p.matches("other-zone.example.com"))
        self.assertFalse(p.matches("zone.example.com"))
        with self.assertRaises(ValueError): Policy("bad;cmd", ("a.zone.example.com",))

    def test_delay_consumes_remaining_ttl(self):
        self.engine.observe(event(),10,1010)
        self.assertFalse(self.engine.tables(60)["work"])

    def test_capacity_failure_is_atomic(self):
        self.engine.max_leases = 1
        e = event(); e["records"].append(dict(e["records"][0], value="192.0.2.2"))
        with self.assertRaises(OverflowError): self.engine.observe(e,0,1000)
        self.assertFalse(self.engine.leases)

    def test_malformed_answer_is_atomic(self):
        e=event(); e["records"].append(dict(e["records"][0], value="not-ip"))
        with self.assertRaises(ValueError): self.engine.observe(e,0,1000)
        self.assertFalse(self.engine.leases)

    def test_clock_safe_restore(self):
        self.engine.observe(event(),0,1000)
        snapshot=self.engine.snapshot(10,1010)
        restored=LeaseEngine(self.engine.policies)
        with self.assertRaises(ValueError): restored.restore(snapshot,0,1020)
        with self.assertRaises(ValueError): restored.restore(snapshot,0,900,True)
        restored.restore(snapshot,0,1020,True)
        self.assertTrue(restored.tables(39)["work"])
        self.assertFalse(restored.tables(40)["work"])

    def test_removed_policy_cannot_reappear_after_restore(self):
        self.engine.observe(event(),0,1000)
        restored=LeaseEngine([Policy("other", ("b.zone.example.com",))])
        restored.restore(self.engine.snapshot(0,1000),0,1001,True)
        self.assertFalse(restored.leases)

    def test_malformed_snapshot_cannot_bypass_clock_or_address_checks(self):
        self.engine.observe(event(),0,1000)
        snapshot=self.engine.snapshot(0,1000)
        for value in (float('nan'),float('inf'),True):
            with self.assertRaises(ValueError): self.engine.restore(snapshot,0,value,True)
        for field,value in [('address','127.0.0.1'),('answer_id','bad identity'),('cname_path',['other.zone.example.com'])]:
            altered=copy.deepcopy(snapshot); altered['leases'][0][field]=value
            with self.assertRaises(ValueError): self.engine.restore(altered,0,1000,True)
        self.assertEqual(self.engine.snapshot(0,1000),snapshot)

    def test_repeated_trailing_dot_is_not_normalized_to_valid_name(self):
        with self.assertRaises(ValueError): Policy('work',('a.zone.example.com..',))


if __name__ == "__main__": unittest.main()
