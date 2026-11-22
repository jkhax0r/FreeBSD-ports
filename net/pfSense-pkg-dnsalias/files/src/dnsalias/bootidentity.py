"""Inactive conservative native boot identity; no reboot or clock changes.

qualify() is pure. capture() reads only two fixed FreeBSD kernel fields using
bounded sysctl subprocesses, outside DNS callbacks. Repeated reads and clock
brackets reject observed drift; they do not provide atomic kernel attestation.
A boot timestamp change, including a wall-clock correction, invalidates recovery
rather than risking a stale lease. Actual reboot qualification remains separate.
"""
import hashlib
import json
import math
import os
import re
import selectors
import subprocess
import sys
import time
import uuid

from .checkpoint import identity
from .replygate import clock


class BootIdentityError(ValueError): pass


def _remaining(deadline):
    value=deadline-time.monotonic()
    if not 0<value<=1: raise BootIdentityError('boot capture deadline exceeded')
    return value


def _read_kernel(name,deadline):
    """Fixed executable/arguments, capped combined output, one shared deadline.

    A failed child is killed/reaped; only this newly created process is touched.
    Cleanup gets at most another 100 ms. No shell or arbitrary sysctl interface.
    """
    if not sys.platform.startswith('freebsd') or name not in ('kern.hostuuid','kern.boottime'):
        raise BootIdentityError('unqualified kernel field or platform')
    _remaining(deadline)
    child=None
    try:
        child=subprocess.Popen(['/sbin/sysctl','-n',name],stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.STDOUT,close_fds=True,
            env={'PATH':'/sbin:/bin','LC_ALL':'C'})
        body=bytearray()
        with selectors.DefaultSelector() as selector:
            os.set_blocking(child.stdout.fileno(),False)
            selector.register(child.stdout,selectors.EVENT_READ)
            while True:
                if not selector.select(_remaining(deadline)):
                    raise BootIdentityError('boot capture deadline exceeded')
                try: part=os.read(child.stdout.fileno(),257-len(body))
                except BlockingIOError: continue
                if not part: break
                body.extend(part)
                if len(body)>256: raise BootIdentityError('kernel response exceeds cap')
        if child.wait(timeout=_remaining(deadline))!=0:
            raise BootIdentityError('kernel identity read failed')
        _remaining(deadline)
        if not body.endswith(b'\n') or body.count(b'\n')!=1:
            raise BootIdentityError('invalid kernel response framing')
        value=bytes(body[:-1]).decode('ascii')
        if not value or any(ord(c)<32 or ord(c)==127 for c in value):
            raise BootIdentityError('invalid kernel response text')
        return value
    except (OSError,UnicodeError,subprocess.TimeoutExpired) as exc:
        raise BootIdentityError('kernel identity read failed: '+type(exc).__name__) from exc
    finally:
        if child is not None:
            if child.stdout is not None: child.stdout.close()
            if child.poll() is None:
                child.kill()
                try: child.wait(timeout=.1)
                except subprocess.TimeoutExpired as exc:
                    raise BootIdentityError('kernel reader cleanup did not finish') from exc


def _host_digest(text):
    if type(text) is not str or not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',text):
        raise BootIdentityError('canonical nonzero kernel host UUID required')
    value=uuid.UUID(text)
    if value.int==0: raise BootIdentityError('nonzero kernel host UUID required')
    return hashlib.sha256(str(value).encode('ascii')).hexdigest()


def _sample_clocks():
    first=clock(time.monotonic());utc=clock(time.time());last=clock(time.monotonic())
    if not 0<=last-first<=.025:
        raise BootIdentityError('clock sample is too slow or discontinuous')
    return {'monotonic':(first+last)/2,'utc':utc,'uncertainty_seconds':(last-first)/2}


def capture(*,budget_seconds=1):
    """Read-only supervisor operation. Never called automatically by observer.

    Four kernel reads and two clock samples within one <=1 s budget; no retries.
    Raw host UUID is omitted from the result. Caller still owns checkpoint,
    process, source and deployment verification. Changed/unknown identity must
    rebuild from fresh trusted replies, never extend an old lease.
    """
    if not sys.platform.startswith('freebsd'):
        raise BootIdentityError('native FreeBSD kernel identity required')
    if type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds) or not 0<budget_seconds<=1:
        raise BootIdentityError('bounded boot capture budget required')
    started=clock(time.monotonic());deadline=started+budget_seconds
    first_host=_host_digest(_read_kernel('kern.hostuuid',deadline))
    first_boot=_read_kernel('kern.boottime',deadline);first=_sample_clocks()
    second_host=_host_digest(_read_kernel('kern.hostuuid',deadline))
    second_boot=_read_kernel('kern.boottime',deadline);second=_sample_clocks()
    ended=clock(time.monotonic())
    if not started<=first['monotonic']<=second['monotonic']<=ended<deadline:
        raise BootIdentityError('boot capture expired or clock regressed')
    if first_host!=second_host:
        raise BootIdentityError('kernel host identity changed during capture')
    before=qualify(first_boot,first_host,now=first['monotonic'],utc_now=first['utc'])
    after=qualify(second_boot,second_host,now=second['monotonic'],utc_now=second['utc'])
    if before['boot_id']!=after['boot_id']:
        raise BootIdentityError('kernel boot identity changed during capture')
    if abs((second['utc']-first['utc'])-(second['monotonic']-first['monotonic']))>.025:
        raise BootIdentityError('wall clock changed during capture')
    return dict(after,format='dnsalias-boot-capture-1',host_id_sha256=second_host,
        sampled_monotonic=second['monotonic'],sampled_utc=second['utc'],
        clock_uncertainty_seconds=max(first['uncertainty_seconds'],second['uncertainty_seconds']),
        started_monotonic=started,finished_monotonic=ended,duration_ms=(ended-started)*1000,
        kernel_reads=4,enforcement_qualified=False)


def qualify(boot_time,host_id_sha256,*,now,utc_now,tolerance=.25):
    identity(host_id_sha256)
    now,utc_now=clock(now),clock(utc_now)
    if type(tolerance) not in (int,float) or not math.isfinite(tolerance) or not 0<tolerance<=.25:
        raise ValueError('conservative boot-clock tolerance required')
    if not isinstance(boot_time,str) or len(boot_time)>256:
        raise ValueError('bounded kernel boot timestamp required')
    match=re.fullmatch(r'\{\s*sec\s*=\s*(\d{1,12}),\s*usec\s*=\s*(\d{1,6})\s*\}(?: [^\r\n]*)?',boot_time)
    if not match: raise ValueError('unqualified kernel boot timestamp format')
    sec,usec=map(int,match.groups())
    if sec<=0 or not 0<=usec<1000000: raise ValueError('invalid kernel boot timestamp')
    boot_utc=sec+usec/1000000
    if boot_utc>utc_now or abs((utc_now-now)-boot_utc)>tolerance:
        raise ValueError('kernel boot time and sampled clocks disagree; rebuild required')
    record={'format':'dnsalias-native-boot-1','host_sha256':host_id_sha256,'seconds':sec,'microseconds':usec}
    return {'boot_id':hashlib.sha256(json.dumps(record,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'boot_utc':boot_utc,'clock_difference_seconds':(utc_now-now)-boot_utc,
            'recovery_policy':'changed identity requires rebuilding from fresh replies'}
