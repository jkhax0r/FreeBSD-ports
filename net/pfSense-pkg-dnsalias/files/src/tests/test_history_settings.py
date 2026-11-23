import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from dnsalias.collector import EventStore
from dnsalias.historylimits import DEFAULT_EVENTS, PROFILES, settings
from dnsalias.trialfeed import FeedTelemetry


class HistorySettingsTests(unittest.TestCase):
    def test_large_report_lock_retries_a_confirmed_rollback_once_released(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite"
            settings(path, 500000)
            store = EventStore(path, "reply", busy_timeout_ms=20)
            feed = object.__new__(FeedTelemetry)
            feed.stop = threading.Event()
            feed.counters = dict(persisted=0, dropped=0, busy_batches=0)
            feed.losses = dict(database_busy=0)
            reader = sqlite3.connect(path)
            try:
                reader.execute("BEGIN")
                reader.execute("SELECT 1 FROM events").fetchall()
                # Release the active read only after an actual failed write rolled back.
                def release_reader(wait):
                    self.assertFalse(store.db.in_transaction)
                    self.assertEqual(reader.execute("SELECT count(*) FROM events").fetchone()[0], 0)
                    reader.rollback()
                    return False
                import time
                event = dict(time=time.time(),kind="dns_query",name="example.com",client="192.0.2.1")
                with patch.object(feed.stop,"wait",side_effect=release_reader) as retry:
                    feed._persist(store,[event])
                retry.assert_called_once()
                self.assertEqual(feed.counters, dict(persisted=1,dropped=0,busy_batches=1))
                self.assertEqual(feed.last_database_busy["dropped"], 0)
                self.assertEqual(reader.execute("SELECT count(*) FROM events").fetchone()[0], 1)
            finally:
                reader.close()
                store.close()

    def test_new_store_and_two_active_writers_follow_a_saved_change(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite"
            self.assertEqual(settings(path), DEFAULT_EVENTS)
            self.assertFalse(path.exists())
            settings(path, 100000)
            first = EventStore(path, "log")
            second = EventStore(path, "reply", reply_details=True)
            try:
                self.assertEqual(first.max_events, 100000)
                self.assertEqual(second.answer_history.limit, 100000)
                event = dict(time=1000, kind="dns_query", name="example.com", client="192.0.2.1")
                self.assertEqual(first.insert([event], now=1000), 1)
                with self.assertRaises(ValueError):
                    settings(path, 30000)
                self.assertEqual(settings(path), 100000)
                settings(path, 20000)
                second.insert([event], now=1000)
                first.prune(1000)
                self.assertEqual(first.storage()["event_limit"], 20000)
                self.assertEqual(second.hourly.max_groups, 20000)
                self.assertEqual(second.answer_history.limit, 20000)
                self.assertEqual(second.dns_reserved_events, 5000)
                self.assertEqual(first.storage()["rows"], 2)
            finally:
                second.close()
                first.close()

    def test_reduction_is_batched_and_preserves_new_events(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite"
            store = EventStore(path, "log")
            try:
                settings(path, 100000)
                event = dict(kind="dns_query",name="example.com",client="192.0.2.1",time=1000)
                for _ in range(11):
                    store.insert([event] * 2000, now=1000)
                settings(path, DEFAULT_EVENTS)
                store.insert([dict(event, time=1001)], now=1001)
                self.assertEqual(store.storage()["rows"], 22000-512)
                for _ in range(4):
                    store.prune(1001)
                self.assertEqual(store.storage()["rows"], 20000)
                self.assertEqual(store.db.execute("SELECT max(time) FROM events").fetchone()[0], 1001)
                self.assertEqual(store.db.execute("SELECT peak_events FROM history_retention").fetchone()[0],100000)
            finally:
                store.close()

    def test_all_profiles_and_legacy_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / "events.sqlite"
            legacy = EventStore(p, "explicit", max_events=32)
            legacy.close()
            self.assertEqual(settings(p), DEFAULT_EVENTS)
            for size, (mib, groups) in PROFILES.items():
                settings(p,size)
                current=EventStore(p, "configured", reply_details=True)
                try:
                    self.assertEqual(current.max_events,size)
                    self.assertEqual(current.max_db_bytes,mib*1024**2)
                    self.assertEqual(current.hourly.max_groups,groups)
                    self.assertEqual(current.answer_history.limit,size)
                    self.assertEqual(current.db.execute("PRAGMA max_page_count").fetchone()[0],current.max_pages)
                finally:
                    current.close()

    def test_existing_large_file_requires_a_saved_budget_and_can_shrink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite"
            settings(path, 100000)
            store = EventStore(path, "log")
            try:
                with store.db:
                    store.db.execute("CREATE TABLE fixture_pages(data BLOB)")
                    store.db.execute("INSERT INTO fixture_pages VALUES(zeroblob(?))", (65 << 20,))
                    store.db.execute("DROP TABLE fixture_pages")
            finally:
                store.close()
            self.assertGreater(path.stat().st_size, 64 << 20)
            settings(path, DEFAULT_EVENTS)
            store = EventStore(path, "log")
            try:
                self.assertEqual(store.max_events, DEFAULT_EVENTS)
                self.assertEqual(store.max_pages, store.db.execute("PRAGMA page_count").fetchone()[0])
                store.insert([dict(kind="dns_query", name="example.com", time=10)], now=10)
                store.db.execute("DROP TABLE history_retention")
                store.db.commit()
            finally:
                store.close()
            with self.assertRaisesRegex(ValueError, "saved history budget"):
                EventStore(path, "log")
            with self.assertRaisesRegex(ValueError, "saved history budget"):
                settings(path, 100000)
