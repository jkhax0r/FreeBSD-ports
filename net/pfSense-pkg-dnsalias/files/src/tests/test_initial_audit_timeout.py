import threading
import time
import unittest

from dnsalias.auditworker import AuditWorker, InitialAuditTimeout
from dnsalias.deployment import DeploymentFingerprint, DeploymentGuard, ProducerIdentity


class FirstAuditTimeoutTests(unittest.TestCase):
    def test_first_timeout_leaves_guard_unqualified_until_full_receipt(self):
        deployment = DeploymentFingerprint('a' * 64, 'b' * 64, 'plain', ())
        producer = ProducerIdentity(7, 59, 'c' * 64, 'd' * 64)
        guard = DeploymentGuard(deployment, producer)
        retry_entered = threading.Event()
        finish = threading.Event()
        calls = []

        def capture():
            calls.append(True)
            if len(calls) == 1:
                raise InitialAuditTimeout()
            retry_entered.set()
            finish.wait(.5)
            return deployment, producer

        worker = AuditWorker(capture)
        worker.start()
        try:
            self.assertTrue(retry_entered.wait(1))
            self.assertIsNone(worker.latest)
            self.assertEqual(worker.apply(guard), 'not_audited')
            finish.set()
            self.wait_until(lambda: worker.latest is not None)
            self.assertEqual(worker.apply(guard), 'qualified')
            self.assertEqual(len(calls), 2)
        finally:
            finish.set()
            worker.close()

    def test_second_timeout_publishes_only_failure(self):
        def capture():
            raise InitialAuditTimeout()

        worker = AuditWorker(capture)
        worker.start()
        try:
            self.wait_until(lambda: worker.failure is not None)
            self.assertEqual(worker.failure, 'audit_initial_read_timed_out')
            self.assertIsNone(worker.latest.deployment)
            self.assertEqual(worker.sequence, 1)
        finally:
            worker.close()

    def wait_until(self, condition):
        deadline = time.monotonic() + 1.5
        while not condition() and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertTrue(condition())
