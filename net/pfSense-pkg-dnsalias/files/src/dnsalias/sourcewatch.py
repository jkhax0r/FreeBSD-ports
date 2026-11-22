"""Native change hints for an already pinned source audit.

Keep every parent and file watched. Only a quiet native queue may reuse the
last exact metadata check. Any change triggers the original complete audit;
errors never qualify, replace files, or establish a new owner. One caller owns
the source audit and this queue. No timers, threads or filesystem writes.
"""
import select

from .sourceaudit import SourceAudit,SourceChanged


class SourceWatch:
    def __init__(self,source):
        if type(source) is not SourceAudit or source.state!='qualified':
            raise ValueError('qualified pinned source audit required')
        self.source=source;self.queue=None;self.state='opening'
        self.descriptors=frozenset(source.fds)
        if not self.descriptors or len(self.descriptors)>SourceAudit.MAX_FILES+SourceAudit.MAX_DIRECTORIES+1:
            raise ValueError('bounded complete source descriptor set required')
        try:
            self.queue=select.kqueue()
            notes=(select.KQ_NOTE_DELETE|select.KQ_NOTE_WRITE|select.KQ_NOTE_EXTEND|
                select.KQ_NOTE_ATTRIB|select.KQ_NOTE_LINK|select.KQ_NOTE_RENAME|select.KQ_NOTE_REVOKE)
            changes=[select.kevent(fd,filter=select.KQ_FILTER_VNODE,
                flags=select.KQ_EV_ADD|select.KQ_EV_ENABLE|select.KQ_EV_CLEAR,fflags=notes)
                for fd in self.descriptors]
            errors=self.queue.control(changes,len(changes),0)
            if any(e.flags&select.KQ_EV_ERROR for e in errors):raise SourceChanged('source watch registration failed')
            # Changes before/during registration must be checked, not adopted.
            source.audit();self.state='ready'
        except Exception:self.close();raise

    def audit(self):
        if self.state!='ready' or self.source.state!='qualified':
            raise SourceChanged('source watch unavailable')
        try:
            events=self.queue.control([],len(self.descriptors),0)
            if any(e.ident not in self.descriptors or e.filter!=select.KQ_FILTER_VNODE
                   or e.flags&select.KQ_EV_ERROR for e in events):
                raise SourceChanged('source watch event unqualified')
            if events:self.source.audit()
        except Exception:
            self.close();raise

    def close(self):
        if self.queue is not None:self.queue.close();self.queue=None
        self.state='closed'
