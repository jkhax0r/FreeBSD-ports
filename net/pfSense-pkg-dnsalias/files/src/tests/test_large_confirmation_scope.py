import unittest
from types import SimpleNamespace
from unittest.mock import Mock

from dnsalias.confirmation import ConfirmationAuthority
from dnsalias.leases import Policy


class LargeConfirmationScopeTests(unittest.TestCase):
    def test_policy_changes_across_index_threshold(self):
        native = Mock()
        native.revoke.return_value = 1
        authority = ConfirmationAuthority(native, object())
        ledger = SimpleNamespace(anchors={})
        writer = SimpleNamespace(ledger=ledger, state="ready")
        authority.writer = writer

        for count in (1, 127, 128, 2048, 1):
            patterns = tuple(f"*.p{i}.example.com" for i in range(count))
            policy = Policy("sample", patterns)
            exact = Policy("other", ("mail.example.com",))
            ledger.policies = (policy, exact)
            authority.prepare_scope(writer)
            self.assertTrue(authority.scope_seeded)
            names = ("example.com", "p0.example.com", "otherp0.example.com",
                     "a.b.p0.example.com", "x.p127.example.com", "mail.example.com",
                     "x.mail.example.com", f"last.p{count - 1}.example.com")
            for name in names:
                with self.subTest(count=count, name=name):
                    self.assertEqual(authority._direct_interest(name),
                                     policy.matches(name) or exact.matches(name))
