"""Optional fail-closed native change notice for already-qualified read-only FDs.

The startup owner supplies and authenticates these descriptors, enrolls this
watch before its final source/lock qualification, and retains that ownership.
No paths are opened, no files read, no PF changes made and no hook is installed.
An event is latched permanently, including changes completed between polls.
This is only a notice, not a shared lock or proof that all mutators are covered.
Filter-lock enrollment is separate. Capability source watches require an
authenticated startup manifest and a final source audit before publication.
"""
import os
import select
import stat
import sys

try:
    import fcntl
except ImportError:
    fcntl=None


class FileChangeBarrier:
    MAX_FILES=32

    def __init__(self,readonly_fds):
        if (not sys.platform.startswith('freebsd') or fcntl is None
            or not all(hasattr(select,n) for n in ('kqueue','kevent','KQ_FILTER_VNODE','KQ_EV_ADD',
                       'KQ_EV_ONESHOT','KQ_NOTE_WRITE','KQ_NOTE_EXTEND','KQ_NOTE_ATTRIB',
                       'KQ_NOTE_LINK','KQ_NOTE_RENAME','KQ_NOTE_DELETE','KQ_NOTE_REVOKE'))):
            raise RuntimeError('qualified FreeBSD vnode notice API required')
        if (type(readonly_fds) not in (list,tuple) or not 1<=len(readonly_fds)<=self.MAX_FILES
            or any(type(fd) is not int or fd<0 for fd in readonly_fds)
            or len(set(readonly_fds))!=len(readonly_fds)):
            raise ValueError('bounded distinct read-only descriptors required')
        self.creator=os.getpid();self.state='enrolling';self.reason=None
        self.queue=None;self.fds=[];self.last_event=None
        self.notes=(select.KQ_NOTE_WRITE|select.KQ_NOTE_EXTEND|select.KQ_NOTE_ATTRIB|
                    select.KQ_NOTE_LINK|select.KQ_NOTE_RENAME|select.KQ_NOTE_DELETE|select.KQ_NOTE_REVOKE)
        try:
            self.queue=select.kqueue();identities=set();before=[];events=[]
            for source in readonly_fds:
                if fcntl.fcntl(source,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY:
                    raise ValueError('read-only descriptor required')
                fd=os.dup(source);os.set_inheritable(fd,False);self.fds.append(fd)
                metadata=self._metadata(fd);identity=metadata[:2]
                if identity in identities:raise ValueError('distinct pinned files required')
                identities.add(identity);before.append(metadata)
                events.append(select.kevent(fd,filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD|select.KQ_EV_ONESHOT,fflags=self.notes))
            self.queue.control(events,0,0)
            if [self._metadata(fd) for fd in self.fds]!=before:
                raise ValueError('file changed during watch enrollment')
            self.state='watching'
            if not self.unchanged():raise ValueError('change noticed during watch enrollment')
        except BaseException:
            self._stop('enrollment_failed');raise

    @staticmethod
    def _metadata(fd):
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:
            raise ValueError('regular single-link source required')
        return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,
                info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

    def _stop(self,reason):
        if self.reason is None:self.reason=reason
        self.state='invalidated'
        if self.queue is not None:
            queue,self.queue=self.queue,None
            try:queue.close()
            except OSError:pass
        descriptors,self.fds=self.fds,[]
        for fd in descriptors:
            try:os.close(fd)
            except OSError:pass

    def unchanged(self):
        if self.state!='watching':return False
        if os.getpid()!=self.creator:
            self._stop('inherited_watch_refused');return False
        try:events=self.queue.control(None,1,0)
        except (OSError,ValueError):
            self._stop('watch_read_failed');return False
        if events:
            event=events[0]
            self.last_event={'descriptor':event.ident,'filter':event.filter,'flags':event.flags,'notes':event.fflags}
            qualified=(event.ident in self.fds and event.filter==select.KQ_FILTER_VNODE
                       and not event.flags&select.KQ_EV_ERROR and bool(event.fflags&self.notes))
            self._stop('file_changed' if qualified else 'watch_event_unqualified')
        return self.state=='watching'

    def close(self):
        self._stop('caller_closed')

    def __enter__(self):return self
    def __exit__(self,*args):self.close()


class CapabilityChangeBarrier(FileChangeBarrier):
    """Watch restricted descriptors against independently captured metadata.

    The root donor must supply an authenticated manifest for its pinned audit
    and recheck named sources after enrollment. Only CAP_EVENT and CAP_FSTAT
    are permitted, so even ancestor FDs outside a chroot grant no traversal.
    This owns duplicates, never the caller's descriptors. It opens no paths.
    Directory child creation is intentionally ignored; directory ownership,
    permissions, removal and rename invalidate the entire watch permanently.
    """
    MAX_FILES=49  # 48 audited sources plus the native filter lock.
    MAX_DIRECTORIES=128

    def __init__(self,entries,*,check_rights):
        if not sys.platform.startswith('freebsd') or not hasattr(select,'kqueue'):
            raise RuntimeError('qualified FreeBSD vnode notice API required')
        if not callable(check_rights):raise ValueError('native capability verifier required')
        if type(entries) not in (list,tuple) or not 1<=len(entries)<=self.MAX_FILES+self.MAX_DIRECTORIES:
            raise ValueError('bounded source watch manifest required')
        count={'file':0,'directory':0};seen=set()
        for entry in entries:
            if type(entry) not in (tuple,list) or len(entry)!=3:raise ValueError('complete watch entry required')
            fd,kind,wanted=entry
            if type(fd) is not int or fd<0 or fd in seen or kind not in count:
                raise ValueError('distinct explicit source descriptor and kind required')
            if (type(wanted) not in (tuple,list) or len(wanted)!=(9 if kind=='file' else 5)
                or any(type(n) is not int for n in wanted)):
                raise ValueError('exact captured source metadata required')
            count[kind]+=1;seen.add(fd)
        if count['file']>self.MAX_FILES or count['directory']>self.MAX_DIRECTORIES:
            raise ValueError('source watch class limit exceeded')
        self.creator=os.getpid();self.state='enrolling';self.reason=None
        self.queue=None;self.fds=[];self.last_event=None
        self.notes=(select.KQ_NOTE_WRITE|select.KQ_NOTE_EXTEND|select.KQ_NOTE_ATTRIB|
                    select.KQ_NOTE_LINK|select.KQ_NOTE_RENAME|select.KQ_NOTE_DELETE|select.KQ_NOTE_REVOKE)
        directory_notes=(select.KQ_NOTE_ATTRIB|select.KQ_NOTE_RENAME|select.KQ_NOTE_DELETE|select.KQ_NOTE_REVOKE)
        try:
            self.queue=select.kqueue();identities=set();captured=[];events=[]
            for source,kind,wanted in entries:
                if check_rights(source) is not True:raise ValueError('watch-only source capability required')
                # dup uses F_DUPFD_CLOEXEC on this qualified platform. Do not
                # use set_inheritable: its ioctl is outside these rights.
                fd=os.dup(source);self.fds.append(fd)
                if os.get_inheritable(fd) or check_rights(fd) is not True:
                    raise ValueError('non-inheritable watch-only duplicate required')
                metadata=self.metadata(fd,kind)
                if metadata!=tuple(wanted) or metadata[:2] in identities:
                    raise ValueError('source manifest differs or repeats an inode')
                identities.add(metadata[:2]);captured.append((fd,kind,metadata))
                events.append(select.kevent(fd,filter=select.KQ_FILTER_VNODE,
                    flags=select.KQ_EV_ADD|select.KQ_EV_ONESHOT,
                    fflags=self.notes if kind=='file' else directory_notes))
            self.queue.control(events,0,0)
            if any(self.metadata(fd,kind)!=wanted for fd,kind,wanted in captured):
                raise ValueError('source changed during capability enrollment')
            self.state='watching'
            if not self.unchanged():raise ValueError('source notice during capability enrollment')
        except BaseException:
            self._stop('enrollment_failed');raise

    @staticmethod
    def metadata(fd,kind):
        info=os.fstat(fd)
        common=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode))
        if kind=='directory' and stat.S_ISDIR(info.st_mode):return common
        if kind=='file' and stat.S_ISREG(info.st_mode) and info.st_nlink==1:
            return common+(info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        raise ValueError('manifest source type or link count differs')
