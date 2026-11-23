"""Excluded reply reasons must describe off-path observations without inventing a DNS or firewall result."""
import unittest
from threading import Event
from unittest.mock import patch

from dnsalias.trialfeed import FeedTelemetry


class Storage:
    def __init__(self):
        self.saved = []
        self.written = Event()

    def insert(self, items):
        self.saved.extend(items)
        if len(self.saved) == 2:
            self.written.set()
        return len(items)

    def close(self):
        self.closed = True


class ReplyExclusions(unittest.TestCase):
    def test_exclusions_remain_distinct_from_storage_loss_and_applied_updates(self):
        profile = '1' * 64
        def outcome(status, reason, name='example.com'):
            reply = {'profile_id': profile, 'resolver_generation': '2' * 32,
                     'client': '192.0.2.1', 'qname': name, 'qtype': 1, 'qclass': 1,
                     'time': 1000.0, 'rcode': 0, 'answer_rrsets': 0, 'records': [],
                     'callback': 'cache', 'reply_flags': 0x8180, 'transport_dropped_before': 0}
            return {'ack': {'status': status}, 'reason': reason, 'ack_transport': 'queued', 'observation': reply}

        store = Storage()
        with patch('dnsalias.trialfeed.EventStore', return_value=store):
            feed = FeedTelemetry('unused', 'session', profile, table_use='dns_aliases')
            feed.offer([outcome('helper_error', 'request_budget_expired'),
                        outcome('helper_error', 'reply_profile_changed'),
                        outcome('ignored', 'unsupported_reply', '.bad..name'),
                        outcome('helper_error', 'reload_busy'),
                        outcome('applied', 'memberships_synchronized_after_ack_deadline')])
            try:
                self.assertTrue(store.written.wait(2))
            finally:
                self.assertTrue(feed.close(1))
        report = feed.status()
        self.assertTrue(store.closed)
        self.assertEqual(report['excluded_by_reason'], {'request_deadline': 1, 'helper_outcome': 1, 'reply_metadata': 1})
        self.assertEqual(report['invalid'], 3)
        self.assertEqual(report['dropped'], 0)
        self.assertEqual(report['offered'], report['persisted'] + report['invalid'])
        self.assertEqual([event['mapping_status'] for event in store.saved],
                         ['reload_busy', 'memberships_synchronized_after_ack_deadline'])
        self.assertFalse(report['dns_waits_for_storage'])
        report['excluded_by_reason']['reply_metadata'] = 42
        self.assertEqual(feed.status()['invalid'], 3)
