import itertools
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dnsalias import confirmationtransport as transport


class EmptyCachedAnswerTests(unittest.TestCase):
    def setUp(self):
        self.event = dict(qname='example.com', qclass=1, qtype=28, callback='cache',
                          extractor_version='unbound-1.26.1-scalars-v1', rcode=0,
                          answer_rrsets=0, records=[], reply_flags=0x8180, reply_ttl=1060,
                          policy_block_registry_match=False, policy_bypass_client=False,
                          transport_dropped_before=0, callback_start_time=1000,
                          time=1000.1, monotonic=100.1, generation_started_monotonic=90,
                          profile_id='b' * 64, resolver_generation='a' * 32)
        serial = itertools.count(1)
        self.client = SimpleNamespace(socket=object(), destination='/private/helper',
                                      helper_pid=42, slot=None, request_id=lambda: f'{next(serial):032x}')
        self.live = True
        self.reader = transport.ConfirmationTransport(
            helper_pid=42, profile_id=self.event['profile_id'], generation=self.event['resolver_generation'],
            started=90, lookup=lambda key: None, alive=lambda: self.live)
        self.send = Mock(return_value='queued')
        self.wait = Mock(return_value='ignored')
        for scope in (patch.object(transport, 'time', SimpleNamespace(monotonic=lambda: 100.1, time=lambda: 1000.1)),
                      patch.object(transport.select, 'select', return_value=([], [], [])),
                      patch.object(transport, 'send_observation', self.send), patch.object(self.reader, '_wait', self.wait)):
            scope.start()
            self.addCleanup(scope.stop)

    def exchange(self, **changes):
        return self.reader.exchange(self.client, self.event | changes, 100.14)

    def test_empty_answers_send_the_full_observation_once_without_claiming_membership(self):
        for changes in ({}, {'qtype': 1}, {'reply_flags': 0x8183}, {'reply_flags': 0x8183, 'rcode': 3}):
            before = self.send.call_count
            self.assertEqual(self.exchange(**changes), 'ignored')
            self.assertEqual(self.send.call_count, before + 1)
            event = self.send.call_args.args[2].copy()
            self.assertIn(event.pop('request_id'), self.reader.pending)
            self.assertEqual(event, self.event | changes)
        self.wait.assert_not_called()
        self.assertEqual(self.reader.reused, 0)

    def test_other_answers_and_unqualified_observations_wait_for_their_own_ack(self):
        for changes in ({'answer_rrsets': 1}, {'records': [{}]}, {'qclass': 3}, {'qtype': 15},
                        {'callback': 'resolved'}, {'reply_flags': 0x8380}, {'reply_flags': 0x8182},
                        {'rcode': 3}, {'reply_ttl': 1000}, {'callback_start_time': 990},
                        {'transport_dropped_before': 1}, {'policy_block_registry_match': True}):
            with self.subTest(changes=changes):
                self.wait.reset_mock()
                self.assertEqual(self.exchange(**changes), 'ignored')
                self.wait.assert_called_once_with(self.client, self.send.call_args.args[2]['request_id'], 100.14)

    def test_change_after_send_waits_for_the_exact_ack_without_resending(self):
        def send_and_invalidate(*args):
            self.live = False
            return 'queued'
        self.send.side_effect = send_and_invalidate
        self.assertEqual(self.exchange(), 'ignored')
        self.send.assert_called_once()
        self.wait.assert_called_once_with(self.client, self.send.call_args.args[2]['request_id'], 100.14)
        self.assertFalse(self.reader.pending)
