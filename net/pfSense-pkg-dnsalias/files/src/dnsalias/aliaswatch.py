"""Lifetime/heartbeat drain for the persistent alias writer; no session timer."""
import errno
import json
import os
from pathlib import Path
import select
import sys
import time
from .membershipgate import ExclusiveMembershipGate
from .pfapi import NativePFTables,_namespace
from .processwatch import ProcessLifetimeWatch
from .reloadlock import SharedReloadLock


def _enroll_confirmation(value,parent):
    """Optional explicit enrollment, before the parent may publish receipts."""
    from .confirmationpage import ConfirmationMapping,contract
    from .nativewire import load
    if (type(value) is not dict or value.keys()!={'native','page','resolver_uid'}
        or type(value['resolver_uid']) is not int or not 0<value['resolver_uid']<(1<<32)):
        raise ValueError('complete confirmation cleanup enrollment required')
    page=contract(value['page'])
    if page['writer_pid']!=parent:raise ValueError('confirmation publisher must be direct service parent')
    native=load(value['native'],'confirmation')
    return ConfirmationMapping.open(native,page,role='revoker',ancestor_uids=(0,value['resolver_uid']))


def _drain(names,fence,confirmation=None):
    # Revoke cached receipts BEFORE waiting for the membership lock. A helper
    # stalled while holding that lock must not leave a reusable page behind.
    if confirmation is not None:confirmation.fence()
    until=time.monotonic()+3
    while True:
        try:fence.__enter__();break
        except Exception:
            if time.monotonic()>=until:raise
            time.sleep(.02)
    try:
        fence.disarm()
        with SharedReloadLock('/tmp/filter.lock'),NativePFTables('',names,writable=True) as native:
            current={}
            for name in names:
                try:current[name]=native.read(name)
                except OSError as exc:
                    # FreeBSD's native address query reports ESRCH for an
                    # absent table. Continue draining the other owned tables.
                    if exc.errno not in (errno.ENOENT,errno.ESRCH):raise
            if current:
                native.names=tuple(current);native.enroll(current)
                for name,addresses in current.items():
                    values=sorted(addresses)
                    for offset in range(0,len(values),512):native.delete(name,set(values[offset:offset+512]))
                native.audit()
                if native.total:raise RuntimeError('alias drain incomplete')
    finally:fence.__exit__()


def run():
    value=json.loads(sys.stdin.buffer.readline(32769));parent=value['parent']
    if parent!=os.getppid():raise ValueError('direct service parent required')
    descriptor=value['gate'];names=_namespace('',tuple(value['tables']))[1]
    fence=ExclusiveMembershipGate(descriptor);watch=ProcessLifetimeWatch(parent)
    confirmation=None;confirmation_identity=None
    started=time.monotonic();pulse=None;shutdown=None;buffer=b''
    try:
        if value.get('confirmation') is not None:
            confirmation=_enroll_confirmation(value['confirmation'],parent)
            confirmation_identity=value['confirmation']
        print(json.dumps({'protected':list(names)}),flush=True)
        while watch.alive() and time.monotonic()<(shutdown if shutdown is not None else started+15 if pulse is None else pulse+5):
            ready,_,_=select.select([sys.stdin.buffer],[],[],.25)
            if not ready:continue
            chunk=os.read(0,32768)
            if not chunk:break
            buffer+=chunk
            if len(buffer)>65536:raise ValueError('watch command too large')
            while b'\n' in buffer:
                line,buffer=buffer.split(b'\n',1)
                if line==b'stopping' and shutdown is None:
                    shutdown=time.monotonic()+15;continue
                if line==b'pulse':pulse=time.monotonic();continue
                new=json.loads(line)
                candidate=_namespace('',tuple(new['tables']))[1]
                if new['parent']!=parent or new['gate']!=descriptor:raise ValueError('watch identity changed')
                if new.get('confirmation')!=confirmation_identity:
                    if confirmation is not None or new.get('confirmation') is None:
                        raise ValueError('confirmation cleanup identity changed')
                    confirmation=_enroll_confirmation(new['confirmation'],parent)
                    confirmation_identity=new['confirmation']
                removed=set(names)-set(candidate)
                if removed:
                    with SharedReloadLock('/tmp/filter.lock'),NativePFTables('',tuple(sorted(removed))) as retired:
                        for name in removed:
                            try:current=retired.read(name)
                            except OSError as exc:
                                if exc.errno not in (errno.ENOENT,errno.ESRCH):raise
                                current=set()
                            if current:raise ValueError('cannot retire populated protection')
                names=candidate;pulse=time.monotonic();print(json.dumps({'protected':list(names)}),flush=True)
    finally:
        # Disarm before reading/removing members. A surviving blocked parent
        # cannot add again after obtaining this shared gate.
        try:
            _drain(names,fence,confirmation)
        finally:
            if confirmation is not None:confirmation.close()
            fence.close();watch.close()


if __name__=='__main__':run()
