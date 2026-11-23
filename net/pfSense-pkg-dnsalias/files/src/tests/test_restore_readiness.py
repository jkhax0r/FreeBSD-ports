"""Check resolver readiness and process observations used during recovery."""
import subprocess
import unittest
from unittest.mock import Mock, patch

from dnsalias.lifecycle import process_command
from dnsalias.trialworker import await_control, match_baseline
from dnsalias.runtimecontrol import RuntimeControlError


class RecordedProcessStatus(unittest.TestCase):
    def lookup(self, code, output, error):
        with patch('subprocess.run', return_value=subprocess.CompletedProcess([], code, output, error)):
            return process_command(12)

    def test_readable_and_reaped_process(self):
        self.assertEqual(self.lookup(0, 'service command\n', ''), 'service command')
        self.assertIsNone(self.lookup(1, '', ''))

    def test_failed_or_incomplete_lookup(self):
        for result in ((2, '', ''), (0, '', ''), (1, ' ', ''), (1, '', 'warning'),
                       (0, 'service command', 'warning'), (0, 'x' * 16385, '')):
            with self.subTest(result=(result[0], len(result[1]), result[2])), self.assertRaises(ValueError):
                self.lookup(*result)


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


class CollectorStopTests(unittest.TestCase):
    def setUp(self):
        from contextlib import ExitStack
        from pathlib import Path
        from tempfile import TemporaryDirectory

        self.stack = self.enterContext(ExitStack())
        self.data = Path(self.stack.enter_context(TemporaryDirectory()))
        self.marker = self.data / 'collector.pid'
        self.marker.write_text('123')
        self.stack.enter_context(patch('manage.verify'))
        self.lookup = self.stack.enter_context(patch('manage.owned_process', return_value=123))
        self.kill = self.stack.enter_context(patch('manage.os.kill'))
        watcher = self.stack.enter_context(patch('dnsalias.processwatch.ProcessLifetimeWatch'))
        self.watch = watcher.return_value.__enter__.return_value
        self.watch.alive.side_effect = [True, False]
        self.watch.state = 'exited'

    def stop(self):
        import manage
        return manage.stop.__wrapped__(self.data / 'source', self.data)

    def test_exit_qualifies_before_parent_reaps_pid(self):
        import signal
        self.assertTrue(self.stop()['stopped'])
        self.assertEqual(self.lookup.call_count, 2)
        self.kill.assert_called_once_with(123, signal.SIGTERM)
        self.assertEqual(self.marker.read_text(), '123')

    def test_changed_identity_before_signal(self):
        self.lookup.side_effect = [123, 124]
        with self.assertRaisesRegex(RuntimeError, 'changed before stop'):
            self.stop()
        self.kill.assert_not_called()

    def test_exec_or_failed_watch_does_not_confirm_exit(self):
        for state in ('changed', 'failed'):
            with self.subTest(state=state):
                self.watch.state = state
                self.watch.alive.side_effect = [True, False]
                with self.assertRaisesRegex(RuntimeError, 'could not be verified'):
                    self.stop()
        self.assertEqual(self.kill.call_count, 2)

    def test_replacement_pid_record_is_preserved(self):
        self.kill.side_effect = lambda *args: self.marker.write_text('124')
        with self.assertRaisesRegex(RuntimeError, 'PID record changed'):
            self.stop()
        self.assertEqual(self.marker.read_text(), '124')
        self.kill.assert_called_once()

    def test_timeout_leaves_worker_and_pid_record_alone(self):
        self.watch.alive.side_effect = [True, True]
        with patch('manage.time.monotonic', side_effect=[0.0, 5.1]), self.assertRaisesRegex(RuntimeError, 'no force kill'):
            self.stop()
        self.kill.assert_called_once()
        self.assertEqual(self.marker.read_text(), '123')
