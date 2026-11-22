"""Explicit bounded PF membership API for the qualified installed native ABI.

No default target, table creation/removal, rule/state operations or startup.
Read-only by default. A writer must compare its caller-supplied membership
baseline before changing addresses. This DOES NOT establish namespace ownership,
trusted DNS leases, reload exclusion, boot identity or watchdog readiness: the
caller must qualify those separately and hold the appropriate native guard.

Routine changes use synchronous kernel add/delete and validate changed counts;
they do not rescan an entire table on the DNS path. Periodic/off-path audit()
compares full memberships. Any uncertain write or observed foreign change
permanently quarantines this instance. Reads remain available for inspection;
there is no automatic mutation retry, adoption or write re-enrollment.
"""
import ctypes as C
import hashlib
import ipaddress
import os
from pathlib import Path
import platform
import re
import socket
import struct

HEADERS={
 '/usr/include/net/pfvar.h':'f72f0e60ff9ea69d9a7de1a68e602324012146b6facb2c34a34b3a86a133e6cb',
 '/usr/include/netpfil/pf/pf.h':'c645ff2ad164057a444a74561c5e6a06e8158df8b267e576b41ef10bc3a893e2',
 '/usr/local/include/libpfctl.h':'a36491b0ba353edf85bbcc4494e7e49484d8e6309643a2a62a78079f9a3bfd90'}
LIBRARY_SHA256='9752d4b11dc9ea35d683a73fb47b5723812fcc60e6c3eeaf55af3c75925d44ba'
MAX_MEMBERS=20000
MAX_BATCH=512
_HOST_ROW=struct.Struct('=16sBBBB')


class PFUnqualified(RuntimeError):pass
class PFUncertain(RuntimeError):pass


class _AddressUnion(C.Union):
    _fields_=[('bytes',C.c_ubyte*16),('words',C.c_uint32*4)]


class _Address(C.Structure):
    _fields_=[('address',_AddressUnion),('family',C.c_uint8),('prefix',C.c_uint8),
        ('negated',C.c_uint8),('feedback',C.c_uint8)]


class _Table(C.Structure):
    _fields_=[('anchor',C.c_char*1024),('name',C.c_char*32),('flags',C.c_uint32),('feedback',C.c_uint8)]


def _namespace(anchor,names):
    if type(anchor) is not str or (anchor!='' and not re.fullmatch('dnsalias_[a-z0-9_]{1,64}',anchor)):
        raise ValueError('explicit main or bounded DNS Alias anchor required')
    if (type(names) is not tuple or not 1<=len(names)<=128
        or any(type(name) is not str or not re.fullmatch('da_[a-z][a-z0-9_]{0,22}',name) for name in names)
        or len(set(names))!=len(names)):
        raise ValueError('explicit unique bounded policy table names required')
    return anchor,tuple(names)


def _addresses(values,limit):
    if type(values) is not set or len(values)>limit or any(type(value) is not str for value in values):
        raise ValueError('bounded explicit host address set required')
    output=[]
    for text in sorted(values):
        if type(text) is not str or '%' in text:raise ValueError('canonical literal host address required')
        address=ipaddress.ip_address(text)
        if str(address)!=text or address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError('canonical non-sinkhole destination required')
        output.append(address)
    return output


def _native_host(family,packed):
    """Canonical host text without constructing an IP object for ordinary rows.

    Native inet_ntop may render mapped/compatible IPv6 with dotted IPv4. Keep
    the existing ipaddress spelling for those exceptional rows so audits and
    enrolled sets compare exactly. Exclusion semantics remain unchanged.
    """
    if family==socket.AF_INET and len(packed)==4:
        if packed==b'\0'*4 or packed[0]==127 or 224<=packed[0]<=239:
            raise PFUnqualified('native table contains excluded destinations')
        return socket.inet_ntop(family,packed)
    if family==socket.AF_INET6 and len(packed)==16:
        if packed in (b'\0'*16,b'\0'*15+b'\1') or packed[0]==255:
            raise PFUnqualified('native table contains excluded destinations')
        value=socket.inet_ntop(family,packed)
        if '.' in value or packed[:12]==b'\0'*10+b'\xff\xff':
            address=ipaddress.IPv6Address(packed)
            if address.is_unspecified or address.is_loopback or address.is_multicast:
                raise PFUnqualified('native table contains excluded destinations')
            return str(address)
        return value
    raise PFUnqualified('unsupported native address layout')


class NativePFTables:
    def forget_empty(self,names):
        """Retire disabled, drained identities; never delete a PF table or rule."""
        _,names=_namespace(self.anchor,tuple(names))
        removed=set(self.names)-set(names)
        if self.state!='enrolled' or not set(names)<=set(self.names) or any(self.known[n] for n in removed):
            raise PFUnqualified('only empty enrolled identities may be retired')
        for n in removed:
            try:current=self.read(n)
            except OSError as exc:
                if exc.errno!=2:raise
                current=set() # Native reload already removed an unused empty table.
            if current:raise PFUnqualified('retired table unexpectedly contains members')
        self.names=names
        for n in removed:
            del self.known[n]
            if self._packed_known is not None:del self._packed_known[n]
        self.audit()

    def extend_empty(self,names):
        """Enroll additional caller-owned empty tables, retaining existing sets."""
        _,names=_namespace(self.anchor,tuple(names))
        if self.state!='enrolled' or not self.writable:raise PFUnqualified('enrolled writer required')
        added=set(names)-set(self.names)
        if not set(self.names)<=set(names):raise PFUnqualified('table ownership cannot be removed during a writer lifetime')
        previous=self.names
        self.names=names
        try:
            snapshot=self.snapshot()
            if any(snapshot[n] for n in added):raise PFUnqualified('new policy table must be empty')
            if any(snapshot[n]!=self.known[n] for n in previous):raise PFUnqualified('existing membership changed')
        except Exception:
            self.names=previous
            raise
        self.known.update({n:set() for n in added})
        if self._packed_known is not None:self._packed_known.update({n:set() for n in added})

    def __init__(self,anchor,names,*,writable=False,max_members=MAX_MEMBERS):
        self.anchor,self.names=_namespace(anchor,names);self.fd=None
        if type(writable) is not bool or type(max_members) is not int or not 1<=max_members<=MAX_MEMBERS:
            raise ValueError('explicit write mode and bounded total membership required')
        if platform.system()!='FreeBSD' or platform.machine()!='amd64' or platform.release()!='16.0-CURRENT':
            raise PFUnqualified('unqualified native platform')
        if writable and os.geteuid()!=0:raise PFUnqualified('native root writer required')
        if (C.sizeof(C.c_void_p),C.sizeof(C.c_int),os.pathconf('/','PC_PATH_MAX'))!=(8,4,1024):
            raise PFUnqualified('unqualified native basic layout')
        if (C.sizeof(_Table),C.alignment(_Table),C.sizeof(_Address),C.alignment(_Address))!=(1064,4,20,4):
            raise PFUnqualified('unqualified table/address structure layout')
        for path,digest in HEADERS.items():
            source=Path(path)
            if source.stat().st_size>2*1024*1024:raise PFUnqualified('native PF header exceeds bound')
            body=source.read_bytes()
            if len(body)>2*1024*1024 or hashlib.sha256(body).hexdigest()!=digest:raise PFUnqualified('native PF headers changed')
        library=Path('/usr/local/lib/libpfctl.so').resolve(strict=True)
        if library.parent!=Path('/usr/local/lib') or not library.name.startswith('libpfctl.so'):
            raise PFUnqualified('native PF library location changed')
        if library.stat().st_size>4*1024*1024 or hashlib.sha256(library.read_bytes()).hexdigest()!=LIBRARY_SHA256:
            raise PFUnqualified('native PF library changed')
        self.library=C.CDLL(str(library),use_errno=True)
        self.get_addrs=self.library.pfctl_table_get_addrs
        self.get_addrs.argtypes=[C.c_int,C.POINTER(_Table),C.POINTER(_Address),C.POINTER(C.c_int),C.c_int]
        self.get_addrs.restype=C.c_int
        self.writable=writable;self.max_members=max_members;self.known=None;self._packed_known=None;self.total=0;self.state='unenrolled';self.reason=None
        if writable:
            self.add_addrs=self.library.pfctl_table_add_addrs;self.del_addrs=self.library.pfctl_table_del_addrs
            for function in (self.add_addrs,self.del_addrs):
                function.argtypes=[C.c_int,C.POINTER(_Table),C.POINTER(_Address),C.c_int,C.POINTER(C.c_int),C.c_int]
                function.restype=C.c_int
        self.fd=os.open('/dev/pf',(os.O_RDWR if writable else os.O_RDONLY)|os.O_CLOEXEC)

    def _table(self,name):
        if self.fd is None:raise PFUnqualified('native table API closed')
        if name not in self.names:raise ValueError('table is outside the explicit policy set')
        table=_Table();table.anchor=self.anchor.encode('ascii');table.name=name.encode('ascii');return table

    def _read(self,name,*,packed_result=False):
        table=self._table(name);entries=(_Address*(self.max_members+1))();size=C.c_int(self.max_members+1)
        C.set_errno(0)
        if self.get_addrs(self.fd,C.byref(table),entries,C.byref(size),0)!=0:
            raise OSError(C.get_errno(),'native membership read failed')
        if not 0<=size.value<=self.max_members:raise PFUnqualified('native membership exceeds bound')
        values=set()
        rows=memoryview(entries).cast('B')[:size.value*_HOST_ROW.size]
        for packed,family,prefix,negated,feedback in _HOST_ROW.iter_unpack(rows):
            if (family not in (socket.AF_INET,socket.AF_INET6) or negated
                or prefix!=(32 if family==socket.AF_INET else 128)):
                raise PFUnqualified('native table contains unsupported entries')
            address=packed[:4] if family==socket.AF_INET else packed
            values.add(address if packed_result else _native_host(family,address))
        if len(values)!=size.value:raise PFUnqualified('native table contains duplicate entries')
        return values

    def read(self,name):return self._read(name)

    def snapshot(self):
        result={};count=0
        for name in self.names:
            result[name]=self.read(name);count+=len(result[name])
            if count>self.max_members:raise PFUnqualified('total membership exceeds bound')
        return result

    def _quarantine(self,reason):
        self.state='quarantined'
        if self.reason is None:self.reason=reason

    def enroll(self,expected):
        if not self.writable or self.state!='unenrolled':raise PFUnqualified('explicit fresh writer required')
        if type(expected) is not dict or set(expected)!=set(self.names):raise ValueError('complete expected membership required')
        # Binary keys reuse the same validated canonical inputs. Four-byte and
        # sixteen-byte keys distinguish families, including mapped IPv6. This
        # bounded index avoids IP parsing/formatting on repeated full audits.
        packed={name:{address.packed for address in _addresses(values,self.max_members)} for name,values in expected.items()}
        if sum(map(len,expected.values()))>self.max_members:raise ValueError('expected membership exceeds total cap')
        try:
            if self.snapshot()!=expected:raise PFUnqualified('native membership differs from expected baseline')
        except Exception:
            self._quarantine('baseline_mismatch_or_unavailable');raise
        self.known={name:set(values) for name,values in expected.items()};self._packed_known=packed
        self.total=sum(map(len,self.known.values()));self.state='enrolled'

    def audit(self):
        if self.state!='enrolled':raise PFUnqualified('enrolled writer required for comparison')
        try:
            count=0
            for name in self.names:
                observed=self._read(name,packed_result=True);count+=len(observed)
                # The enrolled index contains only validated non-sinkhole hosts.
                # Unsupported/excluded destinations cannot match it. Native
                # family/prefix/negation/duplicate checks still run in _read.
                if observed!=self._packed_known[name] or len(observed)!=len(self.known[name]):
                    raise PFUnqualified('native membership changed outside this writer')
                if count>self.max_members:raise PFUnqualified('total membership exceeds bound')
            if count!=self.total:raise PFUnqualified('native membership total differs from baseline')
        except Exception:
            self._quarantine('membership_mismatch_or_unavailable');raise
        return {'matched':True,'members':self.total}

    def _change(self,name,addresses,add):
        if not self.writable or self.state!='enrolled':raise PFUnqualified('writer is not enrolled or is quarantined')
        table=self._table(name);prior=self.known[name]
        if add:
            values=[(address.packed,socket.AF_INET if address.version==4 else socket.AF_INET6)
                for address in _addresses(addresses,MAX_BATCH)]
        else:
            if type(addresses) is not set or len(addresses)>MAX_BATCH or any(type(value) is not str for value in addresses):
                raise ValueError('bounded explicit host address set required')
            if not addresses<=prior:raise ValueError('cannot remove an untracked destination')
            # Already-enrolled canonical hosts need no second Python IP parse.
            # Check against the binary baseline as well before any mutation.
            values=[]
            for value in sorted(addresses):
                family=socket.AF_INET6 if ':' in value else socket.AF_INET
                packed=socket.inet_pton(family,value)
                if packed not in self._packed_known[name]:
                    self._quarantine('baseline_indexes_differ');raise PFUnqualified('native membership baseline indexes differ')
                values.append((packed,family))
        expected=len(addresses-prior) if add else len(addresses)
        if self.total+(expected if add else -expected)>self.max_members:
            raise ValueError('total membership capacity reached')
        if not values:return {'changed':0,'kernel_call':False}
        packed={address for address,family in values}
        rows=b''.join(_HOST_ROW.pack(address.ljust(16,b'\0'),family,32 if family==socket.AF_INET else 128,0,0)
            for address,family in values)
        entries=(_Address*len(values)).from_buffer_copy(rows)
        changed=C.c_int();function=self.add_addrs if add else self.del_addrs
        try:
            C.set_errno(0)
            result=function(self.fd,C.byref(table),entries,len(values),C.byref(changed),0)
            if result!=0:raise OSError(C.get_errno(),'native membership mutation outcome uncertain')
            if changed.value!=expected:raise PFUncertain('kernel count differs from enrolled membership')
            # A local allocation/index failure after the syscall is also an
            # uncertain mutation. Never leave an apparently enrolled writer
            # with only one of its confirmed baselines updated.
            if add:prior.update(addresses);self._packed_known[name].update(packed)
            else:prior.difference_update(addresses);self._packed_known[name].difference_update(packed)
            self.total+=expected if add else -expected
        except Exception as exc:
            self._quarantine('mutation_uncertain');raise PFUncertain('inspect native memberships before any new write') from exc
        return {'changed':changed.value,'kernel_call':True}

    def add(self,name,addresses):return self._change(name,addresses,True)
    def delete(self,name,addresses):return self._change(name,addresses,False)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
        self.state='closed'

    def __enter__(self):return self
    def __exit__(self,*exc):self.close()
