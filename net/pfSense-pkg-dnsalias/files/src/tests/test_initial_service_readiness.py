import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dnsalias.replystartup import ReplyStartup
from dnsalias.runtimecontrol import RuntimeControlError
from dnsalias.trialworker import await_control


class InitialServiceReadinessTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.watch = SimpleNamespace(pid=123, alive=lambda: True)
        self.control = Mock()

    def advance(self, seconds):
        self.now += seconds

    def wait_for_resolver(self, available_after, *, pid=123):
        def status(option, deadline):
            self.assertIsNone(option)
            if self.now < 100 + available_after:
                self.now = deadline
                raise RuntimeControlError('read timed out') from TimeoutError()
            return ('version: 1.26.1\nthreads: 1\nmodules: 2 [ python iterator ]\n'
                    f'uptime: 10 seconds\nunbound (pid {pid}) is running...\n').encode()
        self.control._read.side_effect = status
        with patch('dnsalias.trialworker.time.monotonic', side_effect=lambda: self.now), \
             patch('dnsalias.trialworker.time.sleep', side_effect=self.advance):
            return await_control(self.control, self.watch, persistent_start=True,
                                 budget_seconds=ReplyStartup.INITIAL_SERVICE_SECONDS)

    def test_slow_first_load_rechecks_the_original_resolver(self):
        result = self.wait_for_resolver(9.65)
        self.assertTrue(result['ready'])
        self.assertGreaterEqual(result['elapsed_seconds'], 9.65)
        self.assertLess(result['elapsed_seconds'], 15)

    def test_persistent_start_refuses_late_and_foreign_resolvers(self):
        with self.assertRaises(TimeoutError):
            self.wait_for_resolver(16.5)
        self.assertLessEqual(self.now, 115.01)
        self.now = 100.0
        with self.assertRaisesRegex(ValueError, 'identity changed'):
            self.wait_for_resolver(9.65, pid=124)

    def test_longer_wait_is_limited_to_explicit_service_enrollment(self):
        for kwargs in ({}, {'persistent_start': 1}, {'persistent_start': True, 'replacement_reload': True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await_control(self.control, self.watch, budget_seconds=15, **kwargs)
        self.control._read.assert_not_called()
