import hashlib
import unittest

from dnsalias.confirmationkey import scope_name_keys, scope_policy_key


class PolicyScopeKeyTests(unittest.TestCase):
    def test_large_configuration_keys_match_reply_keys(self):
        for index in range(2048):
            name = f"group{index}.example.com"
            exact = scope_policy_key(name.upper() + ".")
            wildcard = scope_policy_key("*." + name)
            self.assertEqual(exact, hashlib.sha256(("e:" + name).encode()).digest())
            self.assertEqual(wildcard, hashlib.sha256(("s:" + name).encode()).digest())
            self.assertEqual(exact, scope_name_keys(name)[0])
            self.assertIn(wildcard, scope_name_keys("a.b." + name))
            self.assertNotIn(wildcard, scope_name_keys(name))
            self.assertNotIn(wildcard, scope_name_keys("x" + name))

    def test_invalid_saved_scope_names_are_rejected(self):
        for name in ["", "*.", "*.a..example.com", "example.com..", "x" * 64 + ".example.com"]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                scope_policy_key(name)
