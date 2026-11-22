"""Inactive single-use request for Unbound's fixed local TLS reload command.

No default destination, configuration writes, subprocesses, PID signals or retry.
The read-only RuntimeControl API stays read-only. This separate explicit action
requires a caller-owned verified control context and native process watch.
The caller must independently qualify source/config/credentials, lifecycle
coordination and rollback BEFORE calling. An acknowledgement proves only that
the control server accepted the command, never successful hook initialization.
Use outside DNS callbacks; verify actual loaded behavior separately afterward.
"""
import hashlib
import socket
import time

from .processwatch import ProcessLifetimeWatch
from .runtimecontrol import RuntimeControl,RuntimeControlError,status_value


class ReloadRequest:
    def __init__(self,control,watch):
        if not isinstance(control,RuntimeControl) or not isinstance(watch,ProcessLifetimeWatch):
            raise ValueError('explicit verified local control and native watch required')
        # Revalidate and copy endpoint fields so mutating the supplied reader
        # cannot redirect this one-shot action. The caller still owns TLS/watch.
        self.control=RuntimeControl(control.context,address=control.address,port=control.port,
            server_certificate_sha256=control.pin)
        self.watch=watch;self.pid=watch.pid;self.state='new';self.reason=None

    def _alive(self):
        if self.watch.pid!=self.pid or not self.watch.alive():
            raise RuntimeControlError('enrolled resolver lifetime ended')

    def send(self):
        if self.state!='new':raise ValueError('reload request is single-use; inspect before a new operation')
        started=time.monotonic();deadline=started+1;raw=secure=None
        try:
            # This also checks any mutation of the borrowed TLS context.
            reader=RuntimeControl(self.control.context,address=self.control.address,port=self.control.port,
                server_certificate_sha256=self.control.pin)
            self._alive()
            if status_value(reader._read(None,deadline))['pid']!=self.pid:
                raise RuntimeControlError('control service PID mismatch')
            self._alive()
            raw=socket.socket(socket.AF_INET6 if ':' in reader.address else socket.AF_INET,socket.SOCK_STREAM)
            raw.settimeout(reader._remaining(deadline));raw.connect((reader.address,reader.port))
            raw.settimeout(reader._remaining(deadline))
            secure=reader.context.wrap_socket(raw,suppress_ragged_eofs=False)
            if hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()!=reader.pin:
                raise RuntimeControlError('unexpected reload server certificate')
            self._alive();secure.settimeout(reader._remaining(deadline))
            # A failure from this point may follow a partial or complete send.
            # Never retry it automatically, including after a lost response.
            self.state='uncertain'
            secure.sendall(b'UBCT1 reload\n')
            body=bytearray()
            while True:
                secure.settimeout(reader._remaining(deadline))
                part=secure.recv(257-len(body))
                if not part:break
                body.extend(part)
                if len(body)>256:raise RuntimeControlError('reload response exceeds cap')
            reader._remaining(deadline);self._alive()
            if bytes(body)!=b'ok\n':raise RuntimeControlError('reload acknowledgement unqualified')
            self.state='acknowledged'
            return {'accepted':True,'loaded_behavior_verified':False,'automatic_retry':False,
                'pid':self.pid,'duration_ms':(time.monotonic()-started)*1000}
        except Exception as exc:
            if self.state=='new':self.state='refused'
            self.reason=type(exc).__name__
            raise
        finally:
            if secure is not None:secure.close()
            if raw is not None:raw.close()

    def status(self):
        return {'state':self.state,'reason':self.reason,'pid':self.pid,
            'automatic_retry':False,'loaded_behavior_verified':False}
