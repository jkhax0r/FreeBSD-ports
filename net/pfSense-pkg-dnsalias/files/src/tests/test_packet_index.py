import json
import tempfile
import unittest
from pathlib import Path

from dnsalias.collector import EventStore


class PacketIndexTests(unittest.TestCase):
    def test_optional_index_upgrades_existing_history_and_reopens(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.sqlite"
            name = "event_packet_nonweb_counts"
            lookup = "SELECT sql FROM sqlite_master WHERE type='index' AND name=?"
            # A small database keeps the original time-range lookup available.
            store = EventStore(path, "test", max_db_bytes=1024 * 1024)
            with store.db:
                self.assertIsNone(store.db.execute(lookup, (name,)).fetchone())
                for port, protocol in [(443, "tcp"), (80, "udp"), (443, None),
                                       (53, "udp"), (None, "icmp"), (None, None)]:
                    body = json.dumps(dict(destination="192.0.2.9", destination_port=port,
                                           protocol=protocol))
                    store.db.execute("INSERT INTO events(session,time,kind,action,body) "
                                     "VALUES ('test',1,'firewall_packet','pass',?)", (body,))
            store.db.close()
            for _ in range(2):
                store = EventStore(path, "test")
                try:
                    predicate = store.db.execute(lookup, (name,)).fetchone()[0].split("WHERE", 1)[1]
                    self.assertEqual(store.db.execute("SELECT count(*) FROM events").fetchone(), (6,))
                    self.assertEqual(store.db.execute("SELECT count(*) FROM events WHERE " +
                                                      predicate).fetchone(), (4,))
                    self.assertEqual(store.db.execute("PRAGMA integrity_check").fetchone(), ("ok",))
                finally:
                    store.db.close()
