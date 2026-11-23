"""Inactive, bounded read-only Unbound 1.26.1 runtime option capture.

Protocol reference: NLnetLabs/unbound release-1.26.1 smallapp/unbound-control.c
(go_cmd) and daemon/remote.c (do_get_option). Independent implementation.
Only status and a fixed allowlist of get_option commands can be transmitted.
Use outside DNS callbacks, on a supervisor-owned worker. No subprocesses,
remote destinations, setting writes or automatic audits. load_credentials()
separately reads three fixed, explicitly owned local credential files.

Caller supplies a verified mutual TLS context and the exact server certificate
pin from owned files. Certificate chain verification remains mandatory; the
pin identifies the local service instead of a public DNS hostname. Caller must
also qualify those files, process binary/UID/boot and loaded hook generation.
Two equal reads detect observed drift in the running process's config object,
not an atomic snapshot, all workers' applied behavior or hostile ABA changes.
This evidence alone cannot qualify enforcement or loaded Python code.
"""
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import time

from .auditworker import InitialAuditTimeout
from .deployment import SETTINGS,DeploymentFingerprint,ProducerIdentity
from .processwatch import ProcessLifetimeWatch
from .sourceaudit import SourceAudit
from .hookbuild import configuration_fingerprint


class RuntimeControlError(ValueError): pass


class RuntimeDeploymentAudit:
    """Inactive composition for one independently enrolled observer lifetime.

    Caller supplies the complete expected descriptor, owned source capture and
    a worker-owned process watch/control context. All physical descriptor sources
    must have been captured; only the validated observer configuration is virtual.
    Boot identity and loaded generation are qualified separately at controlled
    startup. The receiver keeps its own watch so no kqueue is shared by threads.
    This class neither installs a hook nor adopts changed source/settings.
    """
    def __init__(self,snapshot,producer,*,sources,watch,control,observer_configuration,
                 credential_directory,credential_uid,credential_gid,credential_id,runtime_interval_seconds=0):
        expected=DeploymentFingerprint.from_snapshot(snapshot)
        if type(runtime_interval_seconds) is not int or runtime_interval_seconds not in (0,60):
            raise ValueError('full runtime verification on every audit or every60seconds required')
        self.runtime_interval=runtime_interval_seconds;self.runtime_checked=None;self.runtime_retry_after=0;self.runtime_pending=False
        if not isinstance(producer,ProducerIdentity) or not isinstance(sources,SourceAudit) or sources.state!='qualified':
            raise ValueError('explicit producer and owned source audit required')
        if not isinstance(watch,ProcessLifetimeWatch) or watch.pid!=producer.pid:
            raise ValueError('worker-owned process watch must match producer PID')
        if watch.lifetime_id==producer.process_start_id:
            raise ValueError('worker needs an independent process watch')
        if not isinstance(control,RuntimeControl):raise ValueError('qualified runtime control reader required')
        if type(credential_id) is not str or not re.fullmatch('[a-f0-9]{64}',credential_id):
            raise ValueError('qualified control credential identity required')
        if type(observer_configuration) is not dict or observer_configuration.get('policy_mode')!=snapshot['mode']:
            raise ValueError('matching observer configuration required')
        config_id=configuration_fingerprint(**observer_configuration)
        if config_id!=snapshot['sources']['observer_configuration']:
            raise ValueError('observer configuration fingerprint mismatch')
        # Copy a validated descriptor; caller mutation must not change expected
        # settings or hashes while an audit is in progress.
        self.snapshot=json.loads(json.dumps(snapshot,allow_nan=False))
        self.expected,self.producer=expected,producer
        self.sources,self.watch,self.control=sources,watch,control
        self.directory,self.uid,self.gid=credential_directory,credential_uid,credential_gid
        self.initial_timeout_seen=False
        self.credential_id=credential_id;self.failed=None;self.last_evidence=None
        self.physical={k:v for k,v in self.snapshot['sources'].items() if k!='observer_configuration'}
        if any(sources.hashes.get(k)!=v for k,v in self.physical.items()):
            raise ValueError('every physical deployment source must match the owned capture')

    def capture(self):
        """Return immutable identities only after source/credential/runtime checks.

        One-second soft total budget; all runtime network I/O has the remaining
        deadline. Filesystem calls retain the underlying soft latency limit.
        Extra owned source files are also checked, even if not descriptor fields.
        Caller owns and closes the watch/source audit after the worker stops.
        """
        if self.failed is not None:raise RuntimeControlError('prior deployment audit failure requires a new session')
        started=time.monotonic();deadline=started+1
        def remaining():
            value=deadline-time.monotonic()
            if not 0<value<=1:raise RuntimeControlError('deployment capture deadline exceeded')
            return value
        def source_check():
            result=self.sources.audit(budget_seconds=remaining())
            if any(result['sources'].get(k)!=v for k,v in self.physical.items()):
                raise RuntimeControlError('deployment source changed')
            return result
        def credentials():
            remaining()
            result=load_credentials(self.directory,expected_uid=self.uid,expected_gid=self.gid)
            if result['credential_id']!=self.credential_id or result['server_certificate_sha256']!=self.control.pin:
                raise RuntimeControlError('control credential identity changed')
            remaining();return result
        try:
            if not self.watch.alive():raise RuntimeControlError('producer lifetime ended')
            before=source_check();credentials()
            runtime=None
            if (self.runtime_checked is None or started-self.runtime_checked>=self.runtime_interval) and started>=self.runtime_retry_after:
                try:
                    budget=remaining()
                    if self.runtime_interval:
                        # Startup reads all options twice, before any receipt exists.
                        # Leave time inside the worker deadline for the closing audit.
                        budget=min(.9 if self.runtime_checked is None else .7,budget)
                    runtime=self.control.capture(self.watch,budget_seconds=budget)
                except RuntimeControlError as exc:
                    if (self.runtime_interval and self.runtime_checked is None and not self.initial_timeout_seen
                            and isinstance(exc.__cause__,TimeoutError)):
                        # Discard partial reads. A second capture must verify the
                        # same source, credentials, process and settings from scratch.
                        self.initial_timeout_seen=True
                        raise InitialAuditTimeout() from exc
                    temporary=('deadline' in str(exc) or isinstance(exc.__cause__,(TimeoutError,ConnectionRefusedError,ConnectionResetError)))
                    if not (self.runtime_interval and self.runtime_checked is not None and temporary):raise
                    # A known read-only timeout does not invalidate unchanged
                    # native sources, the watched producer or its loaded hook.
                    # Never update the last-success timestamp or hide the gap.
                    self.runtime_pending=True;self.runtime_retry_after=started+10
                else:
                    if runtime.get('status',{}).get('version')!=self.snapshot['versions']['unbound']:
                        raise RuntimeControlError('effective resolver version changed')
                    if runtime['settings']!=self.snapshot['settings']:
                        raise RuntimeControlError('effective runtime settings changed')
                    self.runtime_checked=started;self.runtime_pending=False;self.runtime_retry_after=0
            credentials();after=source_check();remaining()
            if not self.watch.alive():raise RuntimeControlError('producer lifetime ended')
            self.last_evidence={'started_monotonic':started,'finished_monotonic':time.monotonic(),
                'runtime_ms':runtime['duration_ms'] if runtime else 0,'runtime_requests':runtime['requests'] if runtime else 0,
                'runtime_checked_monotonic':self.runtime_checked,'runtime_settings_interval_seconds':self.runtime_interval,
                'runtime_verification_pending':self.runtime_pending,
                'initial_read_timed_out':self.initial_timeout_seen,
                'runtime_settings_age_seconds':started-self.runtime_checked,
                'source_metadata_ms':before['duration_ms']+after['duration_ms'],
                'source_content_bytes_read':0,'loaded_source_verified':False,'enforcement_qualified':False}
            return self.expected,self.producer
        except InitialAuditTimeout:
            raise
        except Exception as exc:
            self.failed=type(exc).__name__
            raise


def load_credentials(directory,*,expected_uid,expected_gid):
    """Inactive bounded-file loader for the standard Unbound control bundle.

    Three <=16 KiB regular single-link files; fixed names; native owner/group,
    modes, ancestor identities and no symlinks verified before/after TLS load.
    Public certs may be0600/0640/0644; the key must be0600/0640. This performs no
    network operation and never returns raw key bytes or copies keys to disk.

    Native /dev/fd credential paths were unavailable in the private appliance
    probe. OpenSSL therefore uses the qualified names, with a second content
    and metadata audit afterward. This detects observed drift, not hostile
    same-owner/root ABA replacement. Those writers must be lifecycle-coordinated.
    File I/O is bounded in size, not a hard latency guarantee; never a callback.
    """
    if not sys.platform.startswith('freebsd') or not all(hasattr(os,n) for n in ('O_DIRECTORY','O_NOFOLLOW','O_CLOEXEC')):
        raise RuntimeControlError('qualified native credential file API required')
    if (type(expected_uid) is not int or not 0<=expected_uid<2**32 or
        type(expected_gid) is not int or not 0<=expected_gid<2**32):
        raise ValueError('explicit credential owner and group required')
    if type(directory) is not str or len(directory)>512 or not re.fullmatch(r'/[A-Za-z0-9_.\-/]+',directory):
        raise ValueError('bounded absolute credential directory required')
    parts=directory.split('/')[1:]
    if not 1<=len(parts)<=16 or any(p in ('','.','..') for p in parts):
        raise ValueError('canonical credential directory required')
    started=time.monotonic();fds=[];directories=[];files=[]
    def directory_metadata(info):
        mode=stat.S_IMODE(info.st_mode)
        sticky_root=info.st_uid==0 and bool(mode&stat.S_ISVTX)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,expected_uid)
            or mode&0o6000 or (mode&0o022 and not sticky_root)):
            raise RuntimeControlError('credential ancestor ownership or mode refused')
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,mode)
    def verify_directories():
        for parent,name,fd,wanted in directories:
            named=os.stat(name,dir_fd=parent,follow_symlinks=False) if parent is not None else os.stat('/',follow_symlinks=False)
            if directory_metadata(os.fstat(fd))!=wanted or directory_metadata(named)!=wanted:
                raise RuntimeControlError('credential ancestor changed')
    def read_file(fd,name,is_key,parent):
        def metadata(info):
            modes=(0o600,0o640) if is_key else (0o600,0o640,0o644)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=expected_uid or info.st_gid!=expected_gid
                or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink!=1 or not 0<info.st_size<=16384):
                raise RuntimeControlError('credential owner, type, mode, links or size refused')
            return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        before=metadata(os.fstat(fd))
        if metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before:
            raise RuntimeControlError('credential path replaced')
        os.lseek(fd,0,os.SEEK_SET);body=bytearray()
        while len(body)<=16384:
            block=os.read(fd,min(4096,16385-len(body)))
            if not block:break
            body.extend(block)
        if len(body)!=before[5] or metadata(os.fstat(fd))!=before or metadata(os.stat(name,dir_fd=parent,follow_symlinks=False))!=before:
            raise RuntimeControlError('credential changed while reading')
        return bytes(body),(before,hashlib.sha256(body).hexdigest())
    try:
        parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(parent)
        directories.append((None,'/',parent,directory_metadata(os.fstat(parent))))
        for name in parts:
            fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);fds.append(fd)
            directories.append((parent,name,fd,directory_metadata(os.fstat(fd))));parent=fd
        if os.fstat(parent).st_uid!=expected_uid or stat.S_IMODE(os.fstat(parent).st_mode)&0o022:
            raise RuntimeControlError('explicit owned credential directory required')
        verify_directories();server_pem=None
        for name,is_key in (('unbound_server.pem',False),('unbound_control.pem',False),('unbound_control.key',True)):
            if not stat.S_ISREG(os.stat(name,dir_fd=parent,follow_symlinks=False).st_mode):
                raise RuntimeControlError('regular credential file required')
            fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent);fds.append(fd)
            body,fingerprint=read_file(fd,name,is_key,parent);files.append((fd,name,is_key,fingerprint))
            if name=='unbound_server.pem':server_pem=body.decode('ascii')
            del body
        verify_directories()
        pin=hashlib.sha256(ssl.PEM_cert_to_DER_cert(server_pem)).hexdigest()
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False
        context.load_verify_locations(cadata=server_pem)
        context.load_cert_chain(str(Path(directory)/'unbound_control.pem'),str(Path(directory)/'unbound_control.key'),password=lambda: b'')
        for fd,name,is_key,wanted in files:
            body,observed=read_file(fd,name,is_key,parent);del body
            if observed!=wanted:raise RuntimeControlError('credentials changed during TLS load')
        verify_directories()
        fingerprint={'format':'dnsalias-control-credentials-1','directory':directory,
            'directories':[item[3] for item in directories],'files':{name:value for _,name,_,value in files}}
        return {'context':context,'server_certificate_sha256':pin,
            'credential_id':hashlib.sha256(json.dumps(fingerprint,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            'captured_monotonic':time.monotonic(),'duration_ms':(time.monotonic()-started)*1000,
            'loaded_source_verified':False,'enforcement_qualified':False}
    except (OSError,UnicodeError,ssl.SSLError,ValueError) as exc:
        if isinstance(exc,RuntimeControlError):raise
        raise RuntimeControlError('credential capture failed: '+type(exc).__name__) from exc
    finally:
        for fd in reversed(fds):os.close(fd)


EMPTY_OPTIONS=frozenset(('chroot','username','directory','pidfile'))
BOOLEAN_OPTIONS=frozenset(('serve-expired','serve-expired-ttl-reset','serve-original-ttl',
    'prefetch','prefetch-key','qname-minimisation','aggressive-nsec',
    'harden-dnssec-stripped','val-permissive-mode'))
NUMBER_OPTIONS=frozenset(('num-threads','cache-min-ttl','cache-max-ttl','cache-max-negative-ttl',
    'serve-expired-client-timeout','serve-expired-reply-ttl','serve-expired-ttl'))


def option_value(name,body):
    if name not in SETTINGS or type(body) is not bytes or len(body)>257 or not body.endswith(b'\n'):
        raise RuntimeControlError('invalid option response')
    try: value=body[:-1].decode('utf-8')
    except UnicodeError as exc: raise RuntimeControlError('invalid option encoding') from exc
    if (any(ord(c)<32 or ord(c)==127 for c in value) or value.startswith('error')
        or (not value and name not in EMPTY_OPTIONS)):
        raise RuntimeControlError('unsupported or multiline option response')
    if name in BOOLEAN_OPTIONS and value not in ('yes','no'):
        raise RuntimeControlError('invalid boolean option')
    if name in NUMBER_OPTIONS and (not re.fullmatch(r'0|[1-9][0-9]{0,9}',value) or int(value)>2**31-1):
        raise RuntimeControlError('invalid numeric option')
    if name=='num-threads' and not 1<=int(value)<=256:
        raise RuntimeControlError('unqualified worker count')
    return value


def status_value(body):
    if type(body) is not bytes or not 1<=len(body)<=4096:
        raise RuntimeControlError('invalid status response')
    try: text=body.decode('ascii')
    except UnicodeError as exc: raise RuntimeControlError('invalid status encoding') from exc
    if any(ord(c)<32 and c!='\n' or ord(c)==127 for c in text):
        raise RuntimeControlError('invalid status text')
    patterns={'version':r'version: ([A-Za-z0-9_.+-]+)', 'threads':r'threads: ([1-9][0-9]{0,2})',
        'modules':r'modules: ([1-9][0-9]?) \[ ([a-z ]+) \]',
        'uptime':r'uptime: ([0-9]{1,12}) seconds',
        'pid':r'unbound \(pid ([1-9][0-9]{0,9})\) is running\.\.\.'}
    found={}
    for key,pattern in patterns.items():
        matches=re.findall('^'+pattern+'$',text,re.MULTILINE)
        if len(matches)!=1: raise RuntimeControlError('missing or ambiguous runtime status')
        found[key]=matches[0]
    if found['version']!='1.26.1': raise RuntimeControlError('unqualified resolver version')
    count,modules=found['modules'];parts=modules.split()
    if int(count)!=len(parts) or parts.count('python')!=1 or parts.count('iterator')!=1 or any(p not in ('python','validator','iterator') for p in parts):
        raise RuntimeControlError('unqualified module layout')
    return {'version':found['version'],'pid':int(found['pid']),'threads':int(found['threads']),
            'modules':' '.join(parts),'uptime':int(found['uptime'])}


class RuntimeControl:
    def __init__(self,context,*,address,port,server_certificate_sha256):
        if not isinstance(context,ssl.SSLContext) or context.verify_mode!=ssl.CERT_REQUIRED or context.check_hostname:
            raise ValueError('verified TLS context with explicit certificate identity required')
        if type(address) is not str or '%' in address or not ipaddress.ip_address(address).is_loopback:
            raise ValueError('literal loopback destination required')
        if type(port) is not int or not 1<=port<=65535: raise ValueError('explicit control port required')
        if type(server_certificate_sha256) is not str or not re.fullmatch('[a-f0-9]{64}',server_certificate_sha256):
            raise ValueError('explicit server certificate pin required')
        self.context=context;self.address=str(ipaddress.ip_address(address));self.port=port
        self.pin=server_certificate_sha256

    def _remaining(self,deadline):
        value=deadline-time.monotonic()
        if value<=0:
            # An operation may finish just after its socket timeout. Preserve
            # the timeout classification when the next deadline check sees it,
            # so replacement discovery can retry the read within its original
            # budget. Invalid budgets and ownership failures remain final.
            raise RuntimeControlError('runtime capture deadline exceeded') from TimeoutError('runtime control read deadline')
        if not 0<value<=3: raise RuntimeControlError('runtime capture deadline exceeds bounded budget')
        # A restart qualification may allow a longer complete sweep, while
        # each socket operation retains a timeout of at most one second.
        return min(1,value)

    def _read(self,option,deadline):
        # There is deliberately no arbitrary-command method. Validate before
        # opening a socket, even for internal calls and mutated caller contexts.
        if option is not None and (type(option) is not str or option not in SETTINGS):
            raise RuntimeControlError('option not allowlisted')
        if self.context.verify_mode!=ssl.CERT_REQUIRED or self.context.check_hostname:
            raise RuntimeControlError('TLS verification configuration changed')
        command='status' if option is None else 'get_option '+option
        maximum=4096 if option is None else 257
        raw=None;secure=None
        try:
            family=socket.AF_INET6 if ':' in self.address else socket.AF_INET
            raw=socket.socket(family,socket.SOCK_STREAM)
            raw.settimeout(self._remaining(deadline));raw.connect((self.address,self.port))
            raw.settimeout(self._remaining(deadline))
            secure=self.context.wrap_socket(raw,suppress_ragged_eofs=False)
            if hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()!=self.pin:
                raise RuntimeControlError('unexpected control server certificate')
            secure.settimeout(self._remaining(deadline))
            secure.sendall(('UBCT1 '+command+'\n').encode('ascii'))
            body=bytearray()
            while True:
                secure.settimeout(self._remaining(deadline))
                part=secure.recv(min(1024,maximum+1-len(body)))
                if not part: break
                body.extend(part)
                if len(body)>maximum: raise RuntimeControlError('runtime response exceeds cap')
            self._remaining(deadline)
            return bytes(body)
        except (OSError,ValueError) as exc:
            if isinstance(exc,RuntimeControlError): raise
            raise RuntimeControlError('runtime control transport failed: '+type(exc).__name__) from exc
        finally:
            if secure is not None: secure.close()
            if raw is not None: raw.close()

    def capture(self,watch,*,budget_seconds=1):
        """One bounded capture; caller schedules and handles gaps explicitly.

        At most 46 sequential loopback TLS requests, no retries. A certificate,
        status, process, option, deadline or drift failure returns no snapshot.
        Every connection performs full certificate verification and checks the
        exact pin. Explicit TLS session resumption was rejected by the native
        private server and is not used. Process watch and TLS context remain
        owned by the caller.
        """
        if not isinstance(watch,ProcessLifetimeWatch): raise ValueError('native enrolled process watch required')
        if type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds) or not 0<budget_seconds<=3:
            raise ValueError('bounded runtime capture budget required')
        started=time.monotonic();deadline=started+budget_seconds
        def read(option):
            if not watch.alive(): raise RuntimeControlError('resolver lifetime ended')
            return self._read(option,deadline)
        before=status_value(read(None))
        if before['pid']!=watch.pid: raise RuntimeControlError('control service process mismatch')
        first={name:option_value(name,read(name)) for name in sorted(SETTINGS)}
        second={name:option_value(name,read(name)) for name in sorted(SETTINGS)}
        after=status_value(read(None))
        ended=time.monotonic()
        if ended<started or not watch.alive():
            raise RuntimeControlError('runtime capture expired or producer ended')
        if first!=second: raise RuntimeControlError('runtime settings changed during capture')
        if {k:v for k,v in before.items() if k!='uptime'}!={k:v for k,v in after.items() if k!='uptime'}:
            raise RuntimeControlError('runtime status changed during capture')
        # Status uptime is integer seconds. A qualified2..3second replacement
        # sweep can legitimately cross three integer ticks. Keep the original
        # two-tick tolerance for short captures; longer captures use their
        # observed monotonic duration, never merely the requested budget.
        uptime_advance=after['uptime']-before['uptime']
        uptime_limit=max(2,math.ceil(ended-started))
        if not 0<=uptime_advance<=uptime_limit:
            raise RuntimeControlError('runtime uptime outside capture interval: '+str(uptime_advance)+' ticks / '+str(uptime_limit)+' allowed')
        if first['module-config']!=before['modules'] or int(first['num-threads'])!=before['threads']:
            raise RuntimeControlError('runtime status and settings disagree')
        # Both status reads and option snapshots agree. A late final TLS
        # response is a timeout; any identity or setting change above is final.
        if ended>=deadline:
            raise RuntimeControlError('runtime capture deadline exceeded') from TimeoutError('runtime control read deadline')
        return {'format':'dnsalias-runtime-options-1','settings':first,'status':after,
                'process_lifetime_id':watch.lifetime_id,'started_monotonic':started,
                'finished_monotonic':ended,'duration_ms':(ended-started)*1000,
                'requests':2+2*len(SETTINGS),
                'loaded_source_verified':False,'applied_behavior_verified':False,
                'enforcement_qualified':False}
