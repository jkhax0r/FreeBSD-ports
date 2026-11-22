"""Inactive deployment fingerprint and observation freshness gate.

This is not a source inspector or an attestation mechanism. The supervisor
must independently qualify the loaded hook, effective settings, source files,
process start identity and boot identity before constructing this guard. A PID
or a hash of a file on disk alone cannot establish what a running process loaded.
Audits run outside DNS callbacks. Comparing their results is constant-time in
the reply path; this module does not read files, start services or write PF.

Periodic audits have a detection window. Until a qualified native lifecycle
integration closes that window, this guard is for observation, not enforcement.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import math
import re
import time
from .processwatch import ProcessLifetimeWatch
from .ipc import Credentials
from .replygate import ReplyGate

SETTINGS = frozenset(('module-config', 'num-threads', 'cache-min-ttl',
    'cache-max-ttl', 'cache-max-negative-ttl', 'serve-expired',
    'serve-expired-client-timeout', 'serve-expired-reply-ttl', 'serve-expired-ttl',
    'serve-expired-ttl-reset', 'serve-original-ttl', 'prefetch', 'prefetch-key',
    'qname-minimisation', 'aggressive-nsec', 'harden-dnssec-stripped',
    'val-permissive-mode', 'python-script', 'chroot', 'username', 'directory', 'pidfile'))
BASE_SOURCES = frozenset(('resolver_config', 'resolver_binary', 'selected_hook',
                         'services_source', 'unbound_source', 'observer_source',
                         'dispatcher_source', 'extractor_source', 'transport_source',
                         'hook_builder_source','observer_configuration'))
PFB_SOURCES = frozenset(('policy_vendor_hook', 'policy_runtime_include',
                        'policy_vendor_include', 'policy_config', 'policy_package_source'))


def _sha(value):
    if type(value) is not str or not re.fullmatch('[a-f0-9]{64}', value):
        raise ValueError('explicit SHA256 identity required')
    return value


def _clock(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError('bounded monotonic clock required')
    return value


@dataclass(frozen=True)
class DeploymentFingerprint:
    identifier: str
    deployment_id: str
    mode: str
    excluded_addresses: tuple

    @classmethod
    def from_snapshot(cls, snapshot):
        """Fingerprint an explicitly captured complete descriptor, not its trust."""
        if type(snapshot) is not dict or set(snapshot) != {'format', 'mode', 'versions', 'settings', 'sources', 'excluded_addresses'}:
            raise ValueError('complete deployment snapshot required')
        if snapshot['format'] != 'dnsalias-deployment-2' or snapshot['mode'] not in ('plain', 'pfblockerng'):
            raise ValueError('unsupported deployment descriptor')
        mode = snapshot['mode']
        versions, settings, sources = (snapshot[k] for k in ('versions', 'settings', 'sources'))
        version_keys = {'pfsense', 'unbound', 'python'} | ({'pfblockerng'} if mode == 'pfblockerng' else set())
        if type(versions) is not dict or set(versions) != version_keys or versions['unbound'] != '1.26.1':
            raise ValueError('explicit qualified software versions required')
        if any(type(v) is not str or not re.fullmatch(r'[A-Za-z0-9_.+\-]{1,80}', v) for v in versions.values()):
            raise ValueError('invalid version text')
        if type(settings) is not dict or set(settings) != SETTINGS:
            raise ValueError('complete effective resolver settings required')
        empty_allowed={'chroot','username','directory','pidfile'}
        if any(type(v) is not str or not (0 if k in empty_allowed else 1) <= len(v) <= 256 or any(ord(c) < 32 for c in v) for k,v in settings.items()):
            raise ValueError('invalid effective setting text')
        modules = settings['module-config'].split()
        if modules.count('python') != 1 or modules.count('iterator') != 1 or any(m not in ('python', 'validator', 'iterator') for m in modules):
            raise ValueError('unqualified module layout')
        if settings['serve-original-ttl'] != 'no':
            raise ValueError('original TTL replies have not been qualified')
        source_keys = BASE_SOURCES | (PFB_SOURCES if mode == 'pfblockerng' else frozenset())
        if type(sources) is not dict or set(sources) != source_keys:
            raise ValueError('complete source identities required')
        for sha in sources.values(): _sha(sha)
        excluded = snapshot['excluded_addresses']
        if type(excluded) is not list or len(excluded) > 16 or any(type(a) is not str for a in excluded):
            raise ValueError('bounded explicit sinkhole addresses required')
        excluded = tuple(sorted({str(ipaddress.ip_address(a)) for a in excluded}))
        # Serialization copies inputs: subsequent caller mutation cannot alter
        # the expected profile. Sinkhole order/duplicates have no semantics.
        canonical = snapshot | {'excluded_addresses': list(excluded)}
        digest = lambda data: hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        # The generated hook embeds the reply profile ID. Hash its independent
        # source components into that ID and check its final bytes separately,
        # avoiding a self-referential hash while still pinning the whole file.
        core = canonical | {'sources': {k:v for k,v in sources.items() if k != 'selected_hook'}}
        return cls(digest(core), digest(canonical), mode, excluded)

    def __post_init__(self):
        _sha(self.identifier)
        _sha(self.deployment_id)
        if self.mode not in ('plain', 'pfblockerng') or type(self.excluded_addresses) is not tuple:
            raise ValueError('invalid deployment fingerprint')


@dataclass(frozen=True)
class ProducerIdentity:
    pid: int
    uid: int
    boot_id: str
    process_start_id: str

    def __post_init__(self):
        if type(self.pid) is not int or not 0 < self.pid < 2**31 or type(self.uid) is not int or not 0 <= self.uid < 2**32:
            raise ValueError('qualified process identity required')
        _sha(self.boot_id)
        _sha(self.process_start_id)


@dataclass(frozen=True)
class GenerationEnrollment:
    """Evidence from an explicitly controlled hook load, not self-attestation.

    The caller must independently own the load window, inspect the exact source
    before/after that load, and audit the running settings and watched process.
    An old process's reply or a new on-disk file is not a controlled load. This
    record cannot prove all workers or defend against hostile same-UID code.
    """
    profile_id: str
    producer: ProducerIdentity
    generation: str
    started_monotonic: float
    load_open: float
    load_close: float
    received_monotonic: float

    def __post_init__(self):
        _sha(self.profile_id)
        if not isinstance(self.producer, ProducerIdentity):
            raise ValueError('qualified producer required')
        if type(self.generation) is not str or not re.fullmatch('[a-f0-9]{32}',self.generation):
            raise ValueError('explicit resolver generation required')
        for value in (self.started_monotonic,self.load_open,self.load_close,self.received_monotonic): _clock(value)
        if not self.load_open <= self.started_monotonic <= self.received_monotonic <= self.load_close:
            raise ValueError('generation must be observed inside the controlled load window')
        if not 0 < self.load_close-self.load_open <= 30:
            raise ValueError('bounded controlled load window required')

    @classmethod
    def from_reply(cls,reply,credentials,*,expected,producer,load_open,load_close,
                   received_monotonic,received_utc):
        if not isinstance(expected,DeploymentFingerprint) or not isinstance(producer,ProducerIdentity):
            raise ValueError('explicit deployment and producer required')
        if (not isinstance(credentials,Credentials)
            or any(type(n) is not int for n in (credentials.pid,credentials.uid,credentials.euid))
            or (credentials.pid,credentials.uid,credentials.euid)!=(producer.pid,producer.uid,producer.uid)):
            raise ValueError('kernel authenticated producer required')
        if type(reply) is not dict or reply.get('profile_id')!=expected.identifier:
            raise ValueError('reply profile does not match the inspected deployment')
        if type(reply.get('transport_dropped_before')) is not int or reply['transport_dropped_before']!=0:
            raise ValueError('controlled enrollment requires a complete observation feed')
        ReplyGate().accept(reply,received_monotonic=received_monotonic,received_utc=received_utc)
        return cls(expected.identifier,producer,reply['resolver_generation'],
                   reply['generation_started_monotonic'],load_open,load_close,received_monotonic)


class DeploymentGuard:
    def __init__(self, expected, producer, *, freshness_seconds=5,process_watch=None):
        if not isinstance(expected, DeploymentFingerprint) or not isinstance(producer, ProducerIdentity):
            raise ValueError('explicit deployment and process identities required')
        if type(freshness_seconds) not in (int, float) or not math.isfinite(freshness_seconds) or not 0 < freshness_seconds <= 5:
            raise ValueError('bounded audit freshness required')
        self.expected, self.producer = expected, producer
        if process_watch is not None and (not isinstance(process_watch,ProcessLifetimeWatch)
                or process_watch.pid!=producer.pid or process_watch.lifetime_id!=producer.process_start_id):
            raise ValueError('process watch must match the explicitly enrolled producer')
        self.process_watch=process_watch
        self.freshness = freshness_seconds
        self.last_audit = self.last_check = None
        self.suspended_reason = None
        self.generation = None

    def suspend(self, reason='audit_failed'):
        if self.suspended_reason is None:
            self.suspended_reason = reason

    def _advance(self, now):
        if self.process_watch is not None and not self.process_watch.alive():
            self.suspend('producer_lifetime_ended')
        try: now = _clock(now)
        except ValueError:
            self.suspend('audit_clock_invalid'); return False
        if self.last_check is not None and now < self.last_check:
            self.suspend('audit_clock_regressed'); return False
        self.last_check = now
        if self.last_audit is not None and now - self.last_audit >= self.freshness:
            self.suspend('audit_expired')
        return self.suspended_reason is None

    def audit(self, current, producer, *, now, captured_monotonic=None):
        """Supply independently verified inputs. Never recover a suspended session."""
        if not self._advance(now): return False
        if current != self.expected:
            self.suspend('deployment_changed'); return False
        if producer != self.producer:
            self.suspend('producer_changed'); return False
        try: captured=_clock(now if captured_monotonic is None else captured_monotonic)
        except ValueError:
            self.suspend('audit_capture_clock_invalid'); return False
        if (not 0<=now-captured<self.freshness
            or (self.last_audit is not None and captured<self.last_audit)):
            self.suspend('audit_capture_stale'); return False
        # Async delivery must not turn an old observation into a fresh audit.
        # Use the beginning of its capture, not publication/consumption time.
        self.last_audit = captured
        return True

    def check(self, *, now=None):
        now = time.monotonic() if now is None else now
        if not self._advance(now): return self.suspended_reason
        return 'qualified' if self.last_audit is not None else 'not_audited'

    def enroll_generation(self,enrollment,*,now):
        """One explicit enrollment after the independent post-load audit.

        A reload needs a new guard/session; periodic audits cannot silently
        adopt a new generation or revive a suspended observation history.
        """
        if not isinstance(enrollment,GenerationEnrollment): raise ValueError('controlled generation evidence required')
        if self.generation is not None: raise ValueError('generation already enrolled; new session required')
        if (enrollment.profile_id!=self.expected.identifier or enrollment.producer!=self.producer
            or not enrollment.load_close <= _clock(now) < enrollment.received_monotonic+5):
            raise ValueError('matching recent controlled load evidence required')
        if self.check(now=now)!='qualified' or self.last_audit<enrollment.load_close:
            raise ValueError('fresh independent post-load audit required')
        self.generation=enrollment

    def check_generation(self,reply):
        """Constant-time fence after kernel authentication; no I/O or clock reads."""
        if self.suspended_reason is not None: return self.suspended_reason
        if self.generation is None: return 'generation_not_enrolled'
        token,started=reply.get('resolver_generation'),reply.get('generation_started_monotonic')
        if (type(token) is not str or not re.fullmatch('[a-f0-9]{32}',token)
            or type(started) not in (int,float) or not math.isfinite(started) or started<0):
            return 'generation_metadata_invalid'
        if (token,started)!=(self.generation.generation,self.generation.started_monotonic):
            self.suspend('resolver_generation_changed')
            return self.suspended_reason
        return 'qualified'

    def status(self, *, now=None):
        return {'state': self.check(now=now), 'last_audit_monotonic': self.last_audit,
                'freshness_seconds': self.freshness, 'profile_id': self.expected.identifier,
                'deployment_id': self.expected.deployment_id,
                'process_lifetime_watched':self.process_watch is not None,
                'enrolled_generation':self.generation.generation if self.generation is not None else None,
                'mode': self.expected.mode, 'enforcement_qualified': False}
