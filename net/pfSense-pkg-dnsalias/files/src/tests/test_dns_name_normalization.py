import unittest

from dnsalias.leases import dns_name


class DNSNameNormalizationTests(unittest.TestCase):
    def test_ascii_and_idna_forms(self):
        longest = ".".join(("a" * 63, "b" * 63, "c" * 63, "d" * 61))
        for name in ("example.com", "_srv._tcp.example.com", longest):
            self.assertEqual(dns_name(name), name)
            self.assertEqual(dns_name(name.upper() + "."), name)
        self.assertEqual(dns_name("café.example.com"), "xn--caf-dma.example.com")

    def test_invalid_boundaries_use_normal_validation(self):
        for name in ("", ".", ".example.com", "example..com", "example.com..",
                     "a" * 64 + ".example.com", "a b.example.com", "name\n"):
            with self.subTest(name=name), self.assertRaises((ValueError, UnicodeError)):
                dns_name(name)
