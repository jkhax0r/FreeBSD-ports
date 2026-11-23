import json
import signal
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from dnsalias import collector, telemetry


class ObserverStorageTests(unittest.TestCase):
    def run_observer(self, directory, store_factory, step):
        stop = {}
        reader = telemetry.TailReader
        def private_reader(path, limit):
            return reader(directory / Path(path).name, limit)
        def advance(_seconds):
            step(stop[signal.SIGTERM])
        with patch.object(collector, 'EventStore', side_effect=store_factory), \
             patch.object(telemetry, 'TailReader', side_effect=private_reader), \
             patch.object(signal, 'signal', side_effect=stop.__setitem__), \
             patch.object(collector.time, 'sleep', side_effect=advance):
            collector.run(directory, 0, 'dns.log', 'filter.log', rules_enabled=False)

    @staticmethod
    def append_query(path):
        stamp = datetime.now(timezone.utc).isoformat()
        with path.open('a', encoding='utf-8') as log:
            log.write(f'<30>1 {stamp} fixture unbound 1 - - info: query: 192.0.2.1 example.com A IN\n')

    def test_busy_write_rolls_back_then_counts_both_log_records_once(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            log = folder / 'dns.log'
            log.touch()
            path = folder / 'events.sqlite'
            store_type = collector.EventStore
            reader = sqlite3.connect(path)
            steps = []
            def step(stop):
                self.assertLess(len(steps), 3)
                state = json.loads((folder / 'status.json').read_bytes())
                if not steps:
                    reader.execute('BEGIN')
                    reader.execute('SELECT count(*) FROM events').fetchone()
                    self.append_query(log)
                elif len(steps) == 1:
                    self.assertEqual(state['pending_log_events'], 1)
                    self.assertIn('storage_busy_since', state)
                    self.assertEqual(reader.execute('SELECT count(*) FROM events').fetchone(), (0,))
                    self.append_query(log)
                    reader.rollback()
                else:
                    self.assertNotIn('storage_busy_since', state)
                    self.assertEqual(state['pending_log_events'], 0)
                    stop(None, None)
                steps.append(state)
            try:
                self.run_observer(folder, lambda path, session: store_type(path, session, busy_timeout_ms=0), step)
                self.assertEqual(len(steps), 3)
                self.assertEqual(reader.execute('SELECT count(*) FROM events').fetchone(), (2,))
                self.assertEqual(reader.execute('SELECT sum(n) FROM hourly_counts').fetchone(), (2,))
            finally:
                reader.close()

    def test_other_sqlite_errors_stop_the_collector(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            def cannot_open(*args):
                error = sqlite3.OperationalError('invalid database file')
                error.sqlite_errorcode = sqlite3.SQLITE_NOTADB
                raise error
            with self.assertRaises(sqlite3.OperationalError):
                self.run_observer(folder, cannot_open, lambda stop: self.fail('Unexpected retry'))
            state = json.loads((folder / 'status.json').read_bytes())
            self.assertEqual(state['state'], 'failed')
            self.assertEqual(state['counts'].get('storage_busy_polls', 0), 0)

    def test_busy_summary_does_not_repeat_an_already_committed_event(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            log = folder / 'dns.log'
            log.touch()
            store_type = collector.EventStore
            steps = []
            class BusySummary(store_type):
                def status_counts(self):
                    if len(steps) == 1:
                        error = sqlite3.OperationalError('database is busy')
                        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                        raise error
                    return super().status_counts()
            def step(stop):
                self.assertLess(len(steps), 3)
                state = json.loads((folder / 'status.json').read_bytes())
                if not steps:
                    self.append_query(log)
                elif len(steps) == 1:
                    self.assertIn('storage_busy_since', state)
                    self.assertEqual(state['pending_log_events'], 0)
                else:
                    self.assertNotIn('storage_busy_since', state)
                    stop(None, None)
                steps.append(state)
            # Request another status sample after the first log line arrives.
            with patch.object(collector, 'prepare_trial_request', side_effect=lambda *args: {} if len(steps)==1 else None):
                self.run_observer(folder, BusySummary, step)
            with sqlite3.connect(folder / 'events.sqlite') as db:
                self.assertEqual(db.execute('SELECT count(*) FROM events').fetchone(), (1,))
                self.assertEqual(db.execute('SELECT sum(n) FROM hourly_counts').fetchone(), (1,))
            db.close()

    def test_retained_and_raw_counts_share_one_event_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'events.sqlite'
            first = collector.EventStore(path, 'first')
            other = collector.EventStore(path, 'other')
            try:
                self.assertEqual(first.status_counts()['retained'], [])
                query = {'kind':'dns_query', 'time':10, 'name':'example.com'}
                packet = {'kind':'firewall_packet', 'time':15, 'action':'pass'}
                first.insert([query, packet], now=20)
                other.insert([dict(query, time=12), dict(packet, action='block', time=17)], now=20)
                expected = first.summary()
                raw = first.storage()['raw_by_kind']
                storage = first._storage
                def after_grouping(by_kind):
                    other.insert([dict(query, time=19)], now=20)
                    return storage(by_kind)
                with patch.object(first, '_storage', side_effect=after_grouping):
                    sampled = first.status_counts()
                self.assertEqual(sampled['retained'], expected)
                self.assertEqual(sampled['storage']['rows'], 4)
                self.assertEqual(sampled['storage']['raw_by_kind'], raw)
                self.assertEqual(first.storage()['rows'], 5)
            finally:
                other.close()
                first.close()
