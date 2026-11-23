import ssl
import unittest
from unittest.mock import Mock, patch

from dnsalias.auditworker import AuditWorker
from dnsalias.processwatch import ProcessLifetimeWatch
from dnsalias.runtimecontrol import BOOLEAN_OPTIONS, NUMBER_OPTIONS, SETTINGS, RuntimeControl, RuntimeControlError


class ControlReturnDeadlineTests(unittest.TestCase):
    def run_capture(self, *, late=False, ended=False, changed=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        control = RuntimeControl(context, address='127.0.0.1', port=953,
                                 server_certificate_sha256='a' * 64)
        watch = Mock(spec=ProcessLifetimeWatch)
        watch.pid = 123
        watch.lifetime_id = 'test-lifetime'
        watch.alive.return_value = True
        elapsed = 0.0
        status_reads = 0
        value_reads = 0

        def reply(option, deadline):
            nonlocal elapsed, status_reads, value_reads
            if option is None:
                status_reads += 1
                if status_reads == 2:
                    elapsed = .71 if late else .20
                    watch.alive.return_value = not ended
                return (b'version: 1.26.1\nthreads: 1\nmodules: 2 [ python iterator ]\n'
                        b'uptime: 3 seconds\nunbound (pid 123) is running...\n')
            if option == 'cache-min-ttl':
                value_reads += 1
                return b'2\n' if changed and value_reads == 2 else b'1\n'
            if option == 'module-config':
                return b'python iterator\n'
            if option in BOOLEAN_OPTIONS:
                return b'no\n'
            if option in NUMBER_OPTIONS:
                return b'1\n'
            return b'example\n'

        with patch.object(control, '_read', side_effect=reply), patch('dnsalias.runtimecontrol.time') as clock:
            clock.monotonic.side_effect = lambda: 10.0 + elapsed
            return control.capture(watch, budget_seconds=.7)

    def test_timely_complete_capture(self):
        self.assertEqual(self.run_capture()['requests'], 2 + 2 * len(SETTINGS))

    def test_late_complete_capture_is_classified_as_timeout(self):
        with self.assertRaises(RuntimeControlError) as raised:
            self.run_capture(late=True)
        self.assertIsInstance(raised.exception.__cause__, TimeoutError)

    def test_dead_resolver_is_final_even_on_a_late_return(self):
        with self.assertRaises(RuntimeControlError) as raised:
            self.run_capture(late=True, ended=True)
        self.assertNotIsInstance(raised.exception.__cause__, TimeoutError)

    def test_changed_setting_is_final_even_on_a_late_return(self):
        with self.assertRaisesRegex(RuntimeControlError, 'settings changed') as raised:
            self.run_capture(late=True, changed=True)
        self.assertNotIsInstance(raised.exception.__cause__, TimeoutError)

    def test_status_keeps_transport_category_and_elapsed_time(self):
        def refused():
            raise RuntimeControlError('private response') from ConnectionRefusedError('private endpoint')

        worker = AuditWorker(refused)
        self.assertIsNone(worker.status()['last_capture_ms'])
        worker.start()
        try:
            worker.thread.join(1)
            result = worker.status()
            self.assertEqual(result['transport_failure'], 'connection_refused')
            self.assertEqual(result['error'], 'audit_capture_failed:RuntimeControlError')
            self.assertGreaterEqual(result['last_capture_ms'], 0)
            self.assertFalse(result['initial_read_retried'])
            self.assertNotIn('private', str(result))
        finally:
            worker.close()
