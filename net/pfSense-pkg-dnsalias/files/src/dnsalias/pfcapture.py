"""Inactive bounded PF reference capture for an occasional install transaction.

Read every inventoried anchor separately, including unreferenced nested anchors.
Two matching rounds under borrowed native filter/config guards are required.
This is not a scheduler, DNS-path action, PF writer or atomic kernel snapshot.
Privileged writers bypassing the native guard protocol remain out of scope.
Raw rules are private: expose only summary() to logs or UI.
"""
import hashlib
import os
import re
import selectors
import subprocess
import time

from .reloadlock import SharedReloadLock,ExclusiveConfigLock
from .sourceaudit import SourceAudit

PFCTL_SHA256='b50e84dd45af1bce54ae0db438d39e0007cdbe9066db0b00dff3c1270305a7cd'
MAX_ANCHORS=128
MAX_RULE_BYTES=8*1024*1024
MAX_TOTAL_BYTES=16*1024*1024


class PFCaptureError(ValueError):
    def __init__(self,message,*,volatile=False,details=None):
        super().__init__(message);self.volatile=volatile;self.details=details or {}


def _read(args,deadline,max_bytes):
    """Fixed native read command, bounded pipes, owned child always reaped."""
    child=subprocess.Popen(['/sbin/pfctl',*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,env={'PATH':'/sbin:/bin:/usr/sbin:/usr/bin','LC_ALL':'C','LANG':'C'},close_fds=True)
    streams={};data={};selector=selectors.DefaultSelector()
    try:
        for name,stream,cap in (('stdout',child.stdout,max_bytes),('stderr',child.stderr,16384)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,(name,cap))
            streams[name]=stream;data[name]=bytearray()
        while selector.get_map():
            remaining=deadline-time.monotonic()
            if remaining<=0:raise PFCaptureError('native PF read deadline')
            for key,_ in selector.select(min(.05,remaining)):
                name,cap=key.data
                try:chunk=os.read(key.fd,min(65536,cap+1-len(data[name])))
                except BlockingIOError:continue
                if not chunk:selector.unregister(key.fileobj);continue
                data[name].extend(chunk)
                if len(data[name])>cap:raise PFCaptureError('native PF output exceeds bound')
        remaining=deadline-time.monotonic()
        code=child.wait(timeout=remaining) if remaining>0 else None
        if (len(args)==3 and args[0]=='-a' and args[2] in ('-sr','-sn') and code in (0,1,255)
            and not data['stdout'] and data['stderr']==b'pfctl: Anchor does not exist.\n'):
            raise PFCaptureError('native anchor disappeared during capture',volatile=True)
        if remaining<=0 or code!=0 or data['stderr']:
            raise PFCaptureError('native PF read failed or warned')
        return bytes(data['stdout'])
    finally:
        selector.close()
        if child.poll() is None:child.kill()
        child.wait(timeout=1)
        for stream in (child.stdout,child.stderr):stream.close()


def _names(raw,*,anchors):
    if type(raw) is not bytes:raise PFCaptureError('complete native inventory bytes required')
    try:text=raw.decode('ascii')
    except UnicodeError:raise PFCaptureError('unqualified native inventory encoding') from None
    values=[]
    for line in text.splitlines():
        name=line.strip()
        if not name:raise PFCaptureError('empty native inventory line')
        if anchors:
            parts=name.split('/')
            good=len(name)<=512 and len(parts)<=16 and all(re.fullmatch('[A-Za-z0-9_.-]{1,64}',p) and p not in ('.','..') for p in parts)
        else:good=re.fullmatch('[A-Za-z0-9_]{1,128}',name)
        if not good:raise PFCaptureError('unqualified native inventory name')
        values.append(name)
    limit=MAX_ANCHORS if anchors else 10000
    if len(values)>limit or len(set(v.lower() for v in values))!=len(values):
        raise PFCaptureError('native inventory cap or duplicate name')
    return tuple(sorted(values))


class PFReferenceCapture:
    def __init__(self,audit,reload_guard,config_guard):
        if not isinstance(audit,SourceAudit) or audit.state!='qualified' or len(audit.files)!=1:
            raise ValueError('qualified native PF binary capture required')
        spec=audit.files[0][0]
        if (spec.name!='pfctl_binary' or spec.path!='/sbin/pfctl' or spec.uid!=0 or spec.gid!=0
            or spec.modes!=(0o555,) or audit.hashes!={'pfctl_binary':PFCTL_SHA256}):
            raise ValueError('inspected native PF binary required')
        self.audit=audit;self.reload=reload_guard;self.config=config_guard
        self.state='new';self.result=None;self.commands=0;self.bytes=0;self.finished=None
        self.lease=(reload_guard.acquisition,config_guard.acquisition)
        self._guard()

    def _guard(self):
        if (type(self.reload) is not SharedReloadLock or type(self.config) is not ExclusiveConfigLock
            or not self.reload.valid() or not self.config.valid() or self.reload.identity==self.config.identity
            or self.reload.path.name!='filter.lock' or self.config.path.name!='config.lock'
            or self.reload.path.parent!=self.config.path.parent
            or self.lease!=(self.reload.acquisition,self.config.acquisition)):
            raise PFCaptureError('continuous native filter/config guard acquisition required')

    def _command(self,args,cap,deadline):
        self._guard()
        if time.monotonic()>=deadline:raise PFCaptureError('PF capture deadline')
        value=_read(args,deadline,cap);self.commands+=1;self.bytes+=len(value)
        if self.bytes>MAX_TOTAL_BYTES:raise PFCaptureError('PF capture total byte cap')
        self._guard();return value

    def _round(self,deadline):
        anchors=_names(self._command(['-s','Anchors'],65536,deadline),anchors=True)
        tables=_names(self._command(['-s','Tables'],2*1024*1024,deadline),anchors=False)
        result={'anchors':anchors,'existing_tables':tables,'filter_rules':'','nat_rules':''}
        for anchor in ('',*anchors):
            prefix=['-a',anchor] if anchor else []
            for key,flag in (('filter_rules','-sr'),('nat_rules','-sn')):
                raw=self._command([*prefix,flag],MAX_RULE_BYTES,deadline)
                try:text=raw.decode('utf-8')
                except UnicodeError:raise PFCaptureError('unqualified native PF rule encoding') from None
                if re.search('[\x00-\x08\x0b-\x1f\x7f]',text):raise PFCaptureError('native PF rule control bytes')
                result[key]+='# PF anchor '+(anchor or '<root>')+'\n'+text+'\n'
        if _names(self._command(['-s','Anchors'],65536,deadline),anchors=True)!=anchors:
            raise PFCaptureError('native anchor inventory changed during capture',volatile=True)
        return result

    def capture(self):
        if self.state!='new':raise PFCaptureError('PF capture cannot be reused')
        self.state='capturing';start=time.monotonic();deadline=start+2
        try:
            self._guard();self.audit.audit()
            first=self._round(deadline);second=self._round(deadline)
            if first!=second:raise PFCaptureError('native PF references changed between captures',volatile=True)
            self.audit.audit();self._guard()
            if time.monotonic()>=deadline:raise PFCaptureError('PF capture deadline')
            self.result=first;self.finished=time.monotonic();self.elapsed=self.finished-start;self.state='captured'
            return self.summary()
        except Exception as exc:
            self.state='failed';self.result=None
            details={'reason':str(exc) if isinstance(exc,PFCaptureError) else type(exc).__name__,
                     'commands_completed':self.commands,'captured_bytes':self.bytes,'elapsed_ms':(time.monotonic()-start)*1000}
            raise PFCaptureError('PF reference capture failed; inspect and capture afresh',
                volatile=isinstance(exc,PFCaptureError) and exc.volatile,details=details) from None

    def arguments(self):
        """Private publisher inputs valid only during this same guard acquisition."""
        try:
            if self.state!='captured' or time.monotonic()-self.finished>2:
                raise PFCaptureError('PF reference capture is unavailable or stale')
            self._guard();self.audit.audit()
            return {key:self.result[key] for key in ('filter_rules','nat_rules','existing_tables')}
        except Exception:
            self.state='failed';self.result=None
            raise PFCaptureError('PF reference capture no longer qualified') from None

    def summary(self):
        if self.state!='captured':raise PFCaptureError('completed PF capture required')
        return {'anchor_count':len(self.result['anchors']),'root_table_count':len(self.result['existing_tables']),
            'commands':self.commands,'captured_bytes':self.bytes,'elapsed_ms':self.elapsed*1000,
            'filter_sha256':hashlib.sha256(self.result['filter_rules'].encode()).hexdigest(),
            'nat_sha256':hashlib.sha256(self.result['nat_rules'].encode()).hexdigest(),
            'matching_rounds':2,'read_only':True}
