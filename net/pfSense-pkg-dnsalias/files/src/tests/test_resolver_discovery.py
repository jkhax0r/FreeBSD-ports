import threading
import unittest
from unittest.mock import Mock, patch

from dnsalias.resolverreplacement import ResolverReplacement
from dnsalias.runtimecontrol import RuntimeControlError


class PersistentResolverDiscoveryTests(unittest.TestCase):
    def setUp(self):
        worker = object.__new__(ResolverReplacement)
        worker.budget = 12
        worker.wait_for_status = True
        worker.port = 953
        worker.cancelled = threading.Event()
        worker._credentials = Mock(return_value={'context': None, 'server_certificate_sha256': 'fixture'})
        self.worker = worker

    def test_slow_discovery_is_cancellable_without_a_reload(self):
        worker = self.worker
        clock = [100.]
        def unavailable(*args):
            clock[0] += 20
            raise RuntimeControlError('transport unavailable') from ConnectionRefusedError()
        def cancel(seconds):
            self.assertEqual(seconds, 2)
            worker.cancelled.set()
        with patch('dnsalias.resolverreplacement.time.monotonic', side_effect=lambda: clock[0]), \
                patch('dnsalias.resolverreplacement.RuntimeControl') as control, \
                patch.object(worker.cancelled, 'wait', side_effect=cancel):
            control.return_value._read.side_effect = unavailable
            worker._run()
            control.return_value._read.assert_called_once()
        self.assertEqual((worker.result['state'], worker.result['runtime_attempts']), ('cancelled', 0))

    def test_discovery_failure_other_than_transport_is_final(self):
        with patch('dnsalias.resolverreplacement.RuntimeControl') as control:
            worker = self.worker
            control.return_value._read.side_effect = RuntimeControlError('unexpected control server certificate')
            worker._run()
            control.return_value._read.assert_called_once()
        self.assertEqual(worker.result['state'], 'failed')
        self.assertEqual(worker.result['runtime_attempts'], 0)
