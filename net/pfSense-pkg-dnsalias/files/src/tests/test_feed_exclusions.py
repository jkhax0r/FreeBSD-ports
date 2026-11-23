"""Excluded reply reasons must describe off-path observations without inventing a DNS or firewall result."""
import unittest
import queue
import sqlite3
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
        self.assertIsNone(report['last_database_busy'])
        self.assertEqual(report['offered'], report['persisted'] + report['invalid'])
        self.assertEqual([event['mapping_status'] for event in store.saved],
                         ['reload_busy', 'memberships_synchronized_after_ack_deadline'])
        self.assertFalse(report['dns_waits_for_storage'])
        report['excluded_by_reason']['reply_metadata'] = 42
        self.assertEqual(feed.status()['invalid'], 3)

    def test_refused_offers_and_rolled_back_writes_have_distinct_counts(self):
        class BusyStorage(Storage):
            in_transaction = False
            def __init__(self):
                super().__init__()
                self.db = self
            def execute(self, sql):
                self.last_statement = sql
            def insert(self, items):
                self.written.set()
                error = sqlite3.OperationalError('busy')
                error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                raise error

        item = {'ack': {'status': 'ignored'}, 'reason': 'unsupported_reply',
                'ack_transport': 'queued', 'observation': {'client': '192.0.2.1'}}
        store = BusyStorage()
        with patch('dnsalias.trialfeed.EventStore', return_value=store), \
             patch('dnsalias.trialfeed.summarize', return_value={}), \
             patch('dnsalias.trialfeed.describe', return_value={}):
            feed = FeedTelemetry('unused', 'session', '1' * 64)
            try:
                with patch.object(feed.queue, 'put_nowait', side_effect=queue.Full):
                    feed.offer([item])
                feed.offer([item, item])
                self.assertTrue(store.written.wait(2))
            finally:
                self.assertTrue(feed.close(1))
            feed.offer([item])
        report = feed.status()
        self.assertEqual(report['dropped_by_reason'], {'queue_full': 1, 'worker_unavailable': 1, 'database_busy': 2})
        self.assertEqual((report['offered'], report['persisted'], report['dropped'], report['busy_batches']), (4, 0, 4, 1))
        self.assertIsNone(report['error'])
        self.assertEqual(feed.counters['dropped'], report['dropped'])
        self.assertEqual(store.last_statement, 'PRAGMA busy_timeout=650')
        latest = report['last_database_busy']
        self.assertEqual(set(latest), {'operation', 'utc', 'elapsed_ms', 'dropped'})
        self.assertEqual((latest['operation'], latest['dropped']), ('insert', 2))
        self.assertGreater(latest['utc'], 0)
        self.assertGreaterEqual(latest['elapsed_ms'], 0)
        latest['dropped'] = 0
        self.assertEqual(feed.status()['last_database_busy']['dropped'], 2)
        report['dropped_by_reason']['database_busy'] = 0
        self.assertEqual(feed.status()['dropped'], 4)

    def test_stop_shortens_only_the_private_storage_wait_before_draining(self):
        class PausedStorage(Storage):
            def __init__(self):
                super().__init__()
                self.db = self
                self.waits = []
                self.proceed = Event()
            def execute(self, sql):
                self.waits.append(sql)
            def insert(self, items):
                if not self.saved:
                    self.written.set()
                    if not self.proceed.wait(2):
                        raise RuntimeError('test did not release the first insert')
                self.saved.extend(items)
                return len(items)

        item = {'ack': {'status': 'ignored'}, 'reason': 'unsupported_reply',
                'ack_transport': 'queued', 'observation': {'client': '192.0.2.1'}}
        store = PausedStorage()
        with patch('dnsalias.trialfeed.EventStore', return_value=store), \
             patch('dnsalias.trialfeed.summarize', return_value={}), \
             patch('dnsalias.trialfeed.describe', return_value={}):
            feed = FeedTelemetry('unused', 'session', '1' * 64)
            try:
                feed.offer([item])
                self.assertTrue(store.written.wait(2))
                self.assertEqual(store.waits, ['PRAGMA busy_timeout=650'])
                feed.offer([item] * 64)
                self.assertFalse(feed.close(0))
            finally:
                store.proceed.set()
                self.assertTrue(feed.close(1))
        self.assertEqual(store.waits, ['PRAGMA busy_timeout=650', 'PRAGMA busy_timeout=100'])
        self.assertEqual(feed.status()['persisted'], 65)
        self.assertEqual(feed.status()['dropped'], 0)

    def test_stop_counts_queued_records_when_database_never_opened(self):
        entered, release = Event(), Event()

        def busy(*args, **kwargs):
            entered.set()
            if not release.wait(2):
                raise RuntimeError('fixture did not release database open')
            error = sqlite3.OperationalError('busy')
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error

        with patch('dnsalias.trialfeed.EventStore', side_effect=busy):
            feed = FeedTelemetry('unused', 'session', '1' * 64)
            try:
                self.assertTrue(entered.wait(2))
                feed.offer([{}, {}])
                self.assertFalse(feed.close(0))
                self.assertEqual(feed.status()['queued'], 2)
            finally:
                release.set()
                self.assertTrue(feed.close(1))
        report = feed.status()
        self.assertEqual((report['offered'], report['persisted'], report['queued']), (2, 0, 0))
        self.assertEqual(report['dropped_by_reason'], {'queue_full': 0, 'worker_unavailable': 2, 'database_busy': 0})
        self.assertEqual(report['busy_batches'], 1)
        self.assertEqual(report['last_database_busy']['operation'], 'open')
        self.assertEqual(report['last_database_busy']['dropped'], 0)
        self.assertTrue(feed.close(0))
        self.assertEqual(feed.status(), report)

    def test_uncertain_insert_is_separate_from_unattempted_records(self):
        entered, release = Event(), Event()

        class FailedStorage(Storage):
            def insert(self, items):
                entered.set()
                if not release.wait(2):
                    raise RuntimeError('fixture did not release insert')
                raise OSError('write outcome unknown')

        item = {'ack': {'status': 'ignored'}, 'reason': 'unsupported_reply',
                'ack_transport': 'queued', 'observation': {'client': '192.0.2.1'}}
        with patch('dnsalias.trialfeed.EventStore', return_value=FailedStorage()), \
             patch('dnsalias.trialfeed.summarize', return_value={}), \
             patch('dnsalias.trialfeed.describe', return_value={}):
            feed = FeedTelemetry('unused', 'session', '1' * 64)
            try:
                feed.offer([item])
                self.assertTrue(entered.wait(2))
                feed.offer([item, item])
            finally:
                release.set()
                self.assertTrue(feed.close(1))
        report = feed.status()
        self.assertEqual(report['error'], 'OSError')
        self.assertEqual((report['offered'], report['persisted'], report['dropped'], report['queued']), (3, 0, 2, 0))
