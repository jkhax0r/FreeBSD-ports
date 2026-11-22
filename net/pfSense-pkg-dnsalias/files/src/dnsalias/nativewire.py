"""Explicit, startup-only loading of one pinned optional native codec.

No path search, package installation, source adoption, or automatic restart.
The caller supplies an independently audited identity. This module is also
embedded in the resolver companion; it has no relative imports. An already
loaded identical binary is reused across Python-hook reloads. A changed binary
requires a new process because unlinking a CPython extension does not unload it.
"""
import _imp
import hashlib
import importlib.util
import os
import platform
import re
import stat
import sys
import types

NAME='_dnsalias_replywire'
STATE_NAME='_dnsalias_replywire_load_v1'
ABI='cpython-311-freebsd-amd64'
LIMIT=256*1024
FIELDS=frozenset(('path','sha256','device','inode','uid','gid','mode'))
# Closed, package-defined extension identities; callers cannot select arbitrary
# modules or APIs. All use the same pinned ownership and reload protocol.
EXTENSIONS={
    'key':('_dnsalias_confirmationkey','_dnsalias_confirmationkey_load_v1','dnsalias-native-confirmationkey-1',
           'KEY_ABI','KEY_PROTOCOL',('key',)),
    'generation':('_dnsalias_generation','_dnsalias_generation_load_v1','dnsalias-native-generation-1',
                  'GENERATION_ABI','GENERATION_PROTOCOL',('check',)),
    'wire':(NAME,STATE_NAME,'dnsalias-native-wire-1','WIRE_ABI','WIRE_PROTOCOL',('pack','unpack','pack_ack','unpack_ack')),
    'extract':('_dnsalias_replyextract','_dnsalias_replyextract_load_v1','dnsalias-native-extract-1',
               'EXTRACT_ABI','EXTRACT_PROTOCOL',('extract_small',)),
    'confirmation':('_dnsalias_confirmation','_dnsalias_confirmation_load_v1','dnsalias-native-confirmation-1',
                    'CONFIRMATION_ABI','CONFIRMATION_PROTOCOL',
                    ('create_writer','open_reader','open_revoker','revoke','commit','fence','publish','lookup','epoch','close',
                     'scope_add','scope_ready','scope_absent')),
}


def extension(kind):
    if type(kind) is not str or kind not in EXTENSIONS:raise NativeWireError('unknown native extension')
    return EXTENSIONS[kind]


class NativeWireError(ValueError):pass
class NativeWireRestartRequired(NativeWireError):pass


def contract(value):
    if type(value) is not dict or value.keys()!=FIELDS:
        raise NativeWireError('complete native codec identity required')
    path=value['path']
    if (type(path) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,511}',path)
        or any(p in ('','.','..') for p in path.split('/')[1:])
        or type(value['sha256']) is not str or not re.fullmatch('[a-f0-9]{64}',value['sha256'])):
        raise NativeWireError('canonical pinned native codec path/hash required')
    if (any(type(value[k]) is not int for k in ('device','inode','uid','gid','mode'))
        or not -(1<<63)<=value['device']<(1<<64) or not 0<value['inode']<(1<<64)
        or (value['uid'],value['gid'])!=(0,0) or value['mode'] not in (0o400,0o444,0o600)):
        raise NativeWireError('root-owned native codec identity required')
    return dict(value)


def qualified_elf(raw):
    """Structural ABI screen, not a claim that arbitrary native code is safe."""
    return (type(raw) is bytes and 64<=len(raw)<=LIMIT and raw[:7]==b'\x7fELF\x02\x01\x01'
            and raw[7] in (0,9) and raw[16:20]==b'\x03\0\x3e\0' and raw[20:24]==b'\x01\0\0\0')


def _metadata(info,value):
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or not 64<=info.st_size<=LIMIT
        or (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
        !=(value['device'],value['inode'],0,0,value['mode'])):
        raise NativeWireError('native codec file identity changed')
    return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _parents(path):
    # A privileged helper never loads code through an unprivileged ancestor.
    # The resolver may traverse its own chroot directories. In both cases the
    # exact root-owned file identity/hash is pinned by its source profile.
    allowed={0,os.geteuid()};result=[];parent='/'
    for part in ('',*path.split('/')[1:-1]):
        if part:parent=os.path.join(parent,part)
        value=os.lstat(parent);mode=stat.S_IMODE(value.st_mode)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid not in allowed or mode&0o6000
            or mode&0o022 and not (value.st_uid==0 and mode&stat.S_ISVTX)):
            raise NativeWireError('native codec ancestor ownership changed')
        result.append((parent,value.st_dev,value.st_ino,value.st_uid,value.st_gid,mode))
    return result


def _api(module,kind='wire'):
    name,unused_state,unused_owner,abi,protocol,methods=extension(kind)
    if (type(module) is not types.ModuleType or module.__name__!=name
        or getattr(module,abi,None)!=ABI or type(getattr(module,protocol,None)) is not int
        or getattr(module,protocol)!=1
        or any(type(getattr(module,name,None)) is not types.BuiltinFunctionType
               or getattr(module,name).__module__!=module.__name__ for name in methods)):
        raise NativeWireError('native codec ABI or API differs')
    if kind=='confirmation' and any(type(getattr(module,key,None)) is not int or getattr(module,key)!=value
        for key,value in (('PAGE_ABI',3),('PAGE_SIZE',196736),('SLOTS',1024),('WAYS',4))):
        raise NativeWireError('native confirmation layout differs')
    if kind=='confirmation' and any(hasattr(module,key) for key in ('WATCH_FD_ABI','watch_check','watch_restrict')):
        if (type(getattr(module,'WATCH_FD_ABI',None)) is not int or module.WATCH_FD_ABI!=1
            or any(type(getattr(module,key,None)) is not types.BuiltinFunctionType
                or getattr(module,key).__module__!=module.__name__ for key in ('watch_check','watch_restrict'))):
            raise NativeWireError('native watch capability API differs')


def load(value,kind='wire'):
    """Called only during controlled startup, never in a DNS reply callback."""
    name,state_name,owner,unused_abi,unused_protocol,unused_methods=extension(kind)
    value=contract(value)
    if (not sys.platform.startswith('freebsd') or sys.implementation.name!='cpython'
        or sys.version_info[:2]!=(3,11) or platform.machine().lower() not in ('amd64','x86_64')):
        raise NativeWireError('native codec runtime ABI is not qualified')
    parents=_parents(value['path'])
    before=_metadata(os.lstat(value['path']),value)
    fd=os.open(value['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        if _metadata(os.fstat(fd),value)!=before:raise NativeWireError('native codec changed before read')
        chunks=[];size=0
        while size<=LIMIT:
            block=os.read(fd,min(65536,LIMIT+1-size))
            if not block:break
            chunks.append(block);size+=len(block)
        raw=b''.join(chunks)
        if (len(raw)!=before[6] or not qualified_elf(raw)
            or hashlib.sha256(raw).hexdigest()!=value['sha256']):
            raise NativeWireError('native codec bytes or ELF ABI differ')
        def unchanged():
            if (_metadata(os.fstat(fd),value)!=before or _metadata(os.lstat(value['path']),value)!=before
                or _parents(value['path'])!=parents):raise NativeWireError('native codec changed during load')
        unchanged()
        # Shared across independently embedded copies of this source. No
        # unbounded modules accumulate when an unchanged hook reloads.
        _imp.acquire_lock()
        try:
            state=sys.modules.get(state_name);cached=sys.modules.get(name)
            if state is not None:
                if (type(state) is not types.ModuleType or getattr(state,'owner',None)!=owner
                    or getattr(state,'phase',None)!='loaded' or getattr(state,'sha256',None)!=value['sha256']
                    or cached is None or getattr(state,'codec',None) is not cached):
                    raise NativeWireRestartRequired('native codec load differs or is incomplete; new process required')
                _api(cached,kind);unchanged();return cached
            if cached is not None:
                raise NativeWireError('foreign native codec module is not adopted')
            state=types.ModuleType(state_name)
            state.owner=owner;state.phase='loading';state.sha256=value['sha256']
            sys.modules[state_name]=state
            try:
                spec=importlib.util.spec_from_file_location(name,value['path'])
                if spec is None or spec.loader is None:raise NativeWireError('native codec loader unavailable')
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                _api(module,kind);unchanged()
                sys.modules[name]=module;state.codec=module;state.phase='loaded'
                return module
            except BaseException:
                # Loading may already have mapped native code. Never claim it
                # was unloaded or repeat an ambiguous load in this process.
                state.phase='failed'
                raise
        finally:_imp.release_lock()
    finally:os.close(fd)
