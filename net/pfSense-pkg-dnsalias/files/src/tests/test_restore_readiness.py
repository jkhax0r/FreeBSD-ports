"""Check the DNS behavior proof taken after a resolver reload."""
import unittest
from unittest.mock import Mock, patch

from dnsalias.trialworker import await_control, match_baseline
from dnsalias.runtimecontrol import RuntimeControlError


class RestoreReadiness(unittest.TestCase):
    def setUp(self):
        self.now = 0.0
        self.watch = Mock()
        self.watch.alive.return_value = True
        self.probes = [{'name': 'example.com.', 'kind': 1}]
        self.baseline = [{'rcode': 0, 'answers': []}]

    def advance(self, seconds):
        self.now += seconds

    def control_after(self, delay, *, returned_pid=10, **options):
        self.watch.pid = 10
        control = Mock()

        def read(command, deadline):
            if self.now < delay:
                self.now = deadline
                raise RuntimeControlError('connection timed out') from TimeoutError()
            return b'ready'

        control._read.side_effect = read
        with patch('dnsalias.trialworker.time.monotonic', side_effect=lambda: self.now), \
             patch('dnsalias.trialworker.time.sleep', side_effect=self.advance), \
             patch('dnsalias.runtimecontrol.status_value', return_value={'pid': returned_pid}):
            return await_control(control, self.watch, **options)

    def test_replacement_can_finish_a_slow_reload(self):
        result = self.control_after(9.6, budget_seconds=15, replacement_reload=True)
        self.assertTrue(result['ready'])
        self.assertGreaterEqual(result['elapsed_seconds'], 9.6)
        self.assertLess(result['elapsed_seconds'], 15)

    def test_normal_and_replacement_deadlines_and_identity(self):
        with self.assertRaises(ValueError):
            self.control_after(0, budget_seconds=9)
        with self.assertRaises(TimeoutError):
            self.control_after(20)
        self.assertEqual(self.now, 8)
        self.now = 0
        with self.assertRaises(TimeoutError):
            self.control_after(20, budget_seconds=15, replacement_reload=True)
        self.assertEqual(self.now, 15)
        with self.assertRaises(ValueError):
            self.control_after(0, returned_pid=11, budget_seconds=15, replacement_reload=True)

    def match(self, query, **options):
        with patch('dnsalias.trialworker.time.monotonic', side_effect=lambda: self.now), \
                patch('dnsalias.trialworker.time.sleep', side_effect=self.advance), \
                patch('dnsalias.trialworker.query', side_effect=query):
            return match_baseline(self.probes, self.baseline, port=53535, resolver=self.watch, **options)

    def test_slow_persistent_reload_needs_two_matching_answers(self):
        def delayed(name, *, kind, port, timeout_seconds):
            if self.now < 8.9:
                self.advance(timeout_seconds)
                raise TimeoutError()
            return self.baseline[0]

        result = self.match(delayed, persistent=True)
        self.assertTrue(result['matched'])
        self.assertEqual(result['verified_probes'], ['example.com.'] * 2)
        self.assertGreater(result['elapsed_seconds'], 8.9)
        self.assertLess(result['elapsed_seconds'], 12)
        self.assertGreater(result['transport_failures']['timeout'], 0)
        self.now = 0.0
        normal = self.match(delayed)
        self.assertFalse(normal['matched'])
        self.assertEqual(normal['end_condition'], 'deadline')
        self.assertEqual(normal['elapsed_seconds'], 8)

    def test_changed_answer_and_ended_resolver_stop_the_check(self):
        result = self.match(lambda *a, **k: {'rcode': 3, 'answers': []}, persistent=True)
        self.assertFalse(result['matched'])
        self.assertEqual(result['reason'], 'answer_changed')
        self.assertEqual(result['read_attempts'], 1)
        self.watch.alive.return_value = False
        result = self.match(Mock(side_effect=AssertionError('unexpected DNS lookup')), persistent=True)
        self.assertFalse(result['matched'])
        self.assertEqual(result['end_condition'], 'resolver_ended')
        self.assertEqual(result['read_attempts'], 0)

    def test_persistent_deadline_and_transport_categories(self):
        calls = [ConnectionRefusedError(), ConnectionResetError()]
        def timeout(name, *, kind, port, timeout_seconds):
            if calls:
                raise calls.pop(0)
            self.advance(timeout_seconds)
            raise TimeoutError()

        result = self.match(timeout, persistent=True)
        self.assertFalse(result['matched'])
        self.assertEqual(result['verified_probes'], [])
        self.assertEqual(result['elapsed_seconds'], 12)
        failures = result['transport_failures']
        self.assertGreater(failures['timeout'], 0)
        self.assertEqual((failures['refused'], failures['reset']), (1, 1))
        for options in ({'budget_seconds': 9}, {'budget_seconds': 13, 'persistent': True}):
            with self.assertRaises(ValueError):
                self.match(timeout, **options)
