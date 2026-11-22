"""Own one optional codec copy inside the existing per-feed directory.

Only startup and final owned cleanup perform filesystem I/O. The package
binary is loaded by the root helper under root-owned ancestors; the resolver
loads its root-owned readable copy. Both files and the loader remain in the
ordinary source audit. Missing optional assets mean the existing Python path;
partial or changed assets are refused, never repaired or silently adopted.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from .hookfile import _read
from .nativewire import ABI,LIMIT,contract,load,extension
from .sourceaudit import SourceAudit,SourceSpec


class NativeWireAsset:
    kind='wire'
    basename='replywire'

    @classmethod
    def prepare(cls,root,directory,settings,*,resolver_uid,expected_directory=None):
        root,directory=Path(root),Path(directory)
        name,unused_state,owner,unused_abi,unused_protocol,unused_methods=extension(cls.kind)
        prefix='native_'+cls.kind
        paths=[root/'native'/(cls.basename+suffix) for suffix in ('.cpython-311.so','.json','.c')]
        present=[os.path.lexists(path) for path in paths]
        if not any(present):return None
        if not all(present):raise ValueError('partial native codec package requires inspection')
        if os.geteuid()!=0:raise ValueError('native codec publication requires root')
        if (type(expected_directory) is not tuple or len(expected_directory)!=6
            or any(type(v) is not int for v in expected_directory)
            or expected_directory[2]!=0 or expected_directory[4] not in (0o700,0o750)
            or expected_directory[5]!=stat.S_IFDIR):raise ValueError('captured root-owned feed directory required')
        self=cls();self.path=directory/(cls.basename+'.so');self.module=None
        self.copy_label=prefix+'_copy'
        self.ancestor_uids=tuple(dict.fromkeys((0,resolver_uid)))
        self.source_specs=[SourceSpec(prefix+'_binary',str(paths[0]),0,0,(0o600,),LIMIT),
                           SourceSpec(prefix+'_metadata',str(paths[1]),0,0,(0o600,),4096),
                           SourceSpec(prefix+'_c_source',str(paths[2]),0,0,(0o600,),65536),
                           SourceSpec('native_wire_loader',str(root/'dnsalias/nativewire.py'),0,0,(0o600,),65536)]
        with SourceAudit(self.source_specs,ancestor_uids=(0,)) as audit:
            metadata=json.loads(_read(audit,audit.files[1],time.monotonic()+1))
            expected={'format':owner,'module':name,'abi':ABI,'protocol':1,
                      'binary_sha256':audit.hashes[prefix+'_binary'],'source_sha256':audit.hashes[prefix+'_c_source']}
            if type(metadata) is not dict or metadata!=expected or type(metadata.get('protocol')) is not int:
                raise ValueError('native codec package identity differs')
            before=audit.files[0][4]
            helper={'path':str(paths[0]),'sha256':metadata['binary_sha256'],'device':before[0],
                    'inode':before[1],'uid':0,'gid':0,'mode':0o600}
            self.module=load(helper,cls.kind)
            self.helper_contract=contract(helper)
            raw=_read(audit,audit.files[0],time.monotonic()+1)
            self.loader_source=_read(audit,audit.files[3],time.monotonic()+1).decode('utf-8')
            audit.audit()
        # The parent is the fresh root-owned feed directory. Exclusive create
        # and no-follow keep an unexpected file intact, including a symlink.
        self.copy_spec=SourceSpec(self.copy_label,str(self.path),0,0,(0o444,),LIMIT)
        parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            def identity(info):return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),stat.S_IFMT(info.st_mode))
            if identity(os.fstat(parent))!=expected_directory or identity(directory.lstat())!=expected_directory:
                raise ValueError('feed directory ownership changed before native publication')
            fd=os.open(self.path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o444,dir_fd=parent)
            try:
                os.fchown(fd,0,0);os.fchmod(fd,0o444)
                view=memoryview(raw)
                while view:
                    count=os.write(fd,view)
                    if count<=0:raise OSError('short native codec copy')
                    view=view[count:]
                os.fsync(fd);os.fsync(parent)
                created=SourceAudit._file_metadata(os.fstat(fd),self.copy_spec)
            finally:os.close(fd)
        finally:os.close(parent)
        self.source_specs.append(self.copy_spec)
        with SourceAudit(self.source_specs,ancestor_uids=self.ancestor_uids) as audit:
            if audit.hashes[self.copy_label]!=metadata['binary_sha256']:
                raise ValueError('native codec copy changed')
            copied=audit.files[-1][4]
            if copied!=created:raise ValueError('native codec publication identity changed')
            self.copy_identity=copied
            self.sha256=metadata['binary_sha256']
            path=str(Path('/')/self.path.relative_to(settings['chroot'])) if settings['chroot'] else str(self.path)
            self.resolver_contract=contract({'path':path,'sha256':self.sha256,'device':copied[0],
                                            'inode':copied[1],'uid':0,'gid':0,'mode':0o444})
        return self

    def retire(self):
        """Only after the caller has restored the hook and stopped its users."""
        with SourceAudit([self.copy_spec],ancestor_uids=self.ancestor_uids) as audit:
            entry=audit.files[0]
            if entry[4]!=self.copy_identity or audit.hashes[self.copy_label]!=self.sha256:
                raise ValueError('native codec copy ownership changed')
            audit.audit()
            # The pinned root-owned parent prevents a mutable ancestor from
            # redirecting deletion toward an unrelated file.
            os.unlink(entry[2],dir_fd=entry[1]);os.fsync(entry[1])

    def status(self):
        return {'enabled':True,'abi':ABI,'protocol':1,'binary_sha256':self.sha256,
                'bytes':self.copy_identity[6],'reload':'reuse_identical_binary; changed_binary_requires_new_process'}


class NativeExtractAsset(NativeWireAsset):
    kind='extract'
    basename='replyextract'


class NativeGenerationAsset(NativeWireAsset):
    kind='generation'
    basename='generation'


class NativeConfirmationAsset(NativeWireAsset):
    """Optional code asset only; does not create or enroll a mutable page."""
    kind='confirmation'
    basename='confirmation'


class NativeKeyAsset(NativeWireAsset):
    """Optional exact cached-answer key implementation; no reader activation."""
    kind='key'
    basename='confirmationkey'
