import ipaddress
import socket
import unittest

from dnsalias.pfapi import _packed_host


class PFHostCacheTests(unittest.TestCase):
    def test_packed_values_match_canonical_host_spelling(self):
        for text in ("192.0.2.9", "2001:db8::27", "::ffff:c000:209"):
            addr = ipaddress.ip_address(text)
            text = str(addr)
            family = socket.AF_INET if addr.version == 4 else socket.AF_INET6
            self.assertEqual(_packed_host(text), (addr.packed, family))
            self.assertEqual(_packed_host(text), (addr.packed, family))

    def test_related_invalid_spellings_still_fail_after_cache_hit(self):
        _packed_host("2001:db8::27")
        for text in ("2001:0db8::27", "2001:db8::27%1", "2001:db8::27/128",
                     "::", "::1", "127.0.0.1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _packed_host(text)
