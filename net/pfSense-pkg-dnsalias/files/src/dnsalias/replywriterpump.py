"""Inactive bounded native-writer receiver and fixed owned ACK destination.

No process creation, hook/rule activation, file creation, stale socket cleanup,
SQLite work or automatic recovery. Caller owns producer enrollment, provisioned
directories/ancestors, startup handoff, audit scheduling and independent writer
cleanup. In particular, a failed ACK may follow a completed PF update.
"""
import math
import os
from pathlib import Path
import re
import select
import stat
import time

from . import ipc
from .replyendpoint import ReplyEndpoint,NAME,ack_socket_names
from .replywriter import ReplyWriterSession
from .deployment import GenerationEnrollment
from .processwatch import ProcessLifetimeWatch


class ReplyDestination:
    """Pin the generation's fixed ACK sockets before accepting observations.

    Owns only a directory descriptor. It never owns/removes the producer's
    socket, adopts a replacement, or opens/creates another endpoint.
    """
    def __init__(self,directory,*,uid,gid,socket_count=1):
        self.directory=Path(directory);self.path=self.directory/NAME
        self.names=ack_socket_names(socket_count)
        if (os.name!='posix' or not self.directory.is_absolute() or '..' in self.directory.parts
            or len(os.fsencode(self.path))>103 or any(type(n) is not int or not 0<=n<2**32 for n in (uid,gid))):
            raise ValueError('short explicit native producer socket directory required')
        self.uid,self.gid=uid,gid;self.fd=None;self.identity=None;self.state='opening';self.reason=None;self.failure_detail=None
        try:
            self.fd=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            with os.scandir(self.fd) as entries:
                for entry in entries:
                    if entry.name not in self.names:raise ValueError('unexpected producer ACK endpoint')
            self.identity=self._directory()
            self.sockets={name:self._socket(name) for name in self.names}
            self.paths=tuple(str(self.directory/name) for name in self.names)
            self.state='ready'
        except Exception:self.close();raise

    def _directory(self):
        opened=os.fstat(self.fd);named=self.directory.lstat()
        for directory in (opened,named):
            if (not stat.S_ISDIR(directory.st_mode) or (directory.st_uid,directory.st_gid)!=(self.uid,self.gid)
                or stat.S_IMODE(directory.st_mode)!=0o700):raise ValueError('producer ACK directory changed')
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):
            raise ValueError('producer ACK directory replaced')
        return opened.st_dev,opened.st_ino

    def _socket(self,name):
        item=os.stat(name,dir_fd=self.fd,follow_symlinks=False)
        if (not stat.S_ISSOCK(item.st_mode) or (item.st_uid,item.st_gid)!=(self.uid,self.gid) or stat.S_IMODE(item.st_mode)!=0o600
            or item.st_nlink!=1):raise ValueError('producer ACK socket changed')
        return item.st_dev,item.st_ino

    def healthy(self,slot=0):
        if self.state!='ready':return False
        try:
            name=self.names[slot]
            if self._directory()!=self.identity or self._socket(name)!=self.sockets[name]:
                raise ValueError('producer ACK path replaced')
            return True
        except (OSError,ValueError) as exc:
            return self._changed(exc)

    def _changed(self,exc):
        self.failure_detail=(type(exc).__name__+(': '+str(exc)[:160] if isinstance(exc,ValueError) else ' errno='+str(exc.errno)))
        self.reason='ack_destination_changed';self.close();return False

    def audit(self):
        """Check dormant worker paths as part of the scheduled ownership audit."""
        if not self.healthy():return False
        try:
            with os.scandir(self.fd) as entries:
                for entry in entries:
                    if entry.name not in self.sockets:raise ValueError('unexpected producer ACK endpoint')
            for name in self.names[1:]:
                if self._socket(name)!=self.sockets[name]:
                    raise ValueError('producer worker ACK path replaced: '+name)
            return True
        except (OSError,ValueError) as exc:
            return self._changed(exc)

    def status(self):
        return {'state':self.state,'reason':self.reason,'path':str(self.path),'failure_detail':self.failure_detail}

    def send(self,endpoint,ack,*,deadline):
        if (not isinstance(endpoint,ReplyEndpoint) or type(ack) is not dict or set(ack)!={'request_id','status'}
            or type(ack.get('request_id')) is not str or not re.fullmatch('[a-f0-9]{32}',ack['request_id'])
            or ack.get('status') not in ('applied','ignored','helper_error')
            or type(deadline) not in (int,float) or not math.isfinite(deadline)):
            raise ValueError('bounded ACK candidate and owned helper endpoint required')
        slot=0
        if len(self.names)>1:
            if ack['request_id'][0]!='e':return 'invalid_slot'
            slot=int(ack['request_id'][1],16)
            if slot>=len(self.names):return 'invalid_slot'
        if not self.healthy(slot) or not endpoint.healthy():return 'endpoint_changed'
        if not 0<deadline-time.monotonic()<=.05:return 'deadline'
        return ipc.send_observation(endpoint.socket,self.paths[slot],ack)

    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
        self.state='closed'


class GenerationPathReceipt:
    """Retire only a captured ACK directory after its native producer exits.

    No discovery or stale-path adoption. Capture while the qualified route is
    live. Keep its native main-loop watch until retirement. Unexpected files,
    replacement inodes or an uncertain unlink/rmdir require inspection.
    """
    def __init__(self,destination,enrollment):
        if (type(destination) is not ReplyDestination or not destination.healthy()
            or not isinstance(enrollment,GenerationEnrollment)
            or destination.uid!=enrollment.producer.uid
            or destination.directory.name!='g-'+enrollment.generation):
            raise ValueError('live pinned generation ACK route and controlled enrollment required')
        self.parent=destination.directory.parent;self.name=destination.directory.name
        self.uid,self.gid=destination.uid,destination.gid;self.identity=destination.identity
        self.sockets=dict(destination.sockets)
        self.enrollment=enrollment;self.parent_fd=self.directory_fd=None;self.parent_identity=None
        self.state='capturing';self.result=None
        try:
            self.parent_fd=os.open(self.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self.directory_fd=os.dup(destination.fd);self.parent_identity=self._parent()
            self._directory()
            if self._inspect_sockets()!=set(self.sockets):raise ValueError('captured generation is incomplete')
            self.state='captured'
        except Exception:self.close();raise

    def _parent(self):
        opened=os.fstat(self.parent_fd);named=self.parent.lstat()
        for value in (opened,named):
            if not stat.S_ISDIR(value.st_mode) or (value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode))!=(self.uid,self.gid,0o700):
                raise ValueError('ACK parent ownership changed')
        if (opened.st_dev,opened.st_ino)!=(named.st_dev,named.st_ino):raise ValueError('ACK parent replaced')
        result=opened.st_dev,opened.st_ino
        if self.parent_identity not in (None,result):raise ValueError('captured ACK parent replaced')
        return result

    def _directory(self):
        self._parent();opened=os.fstat(self.directory_fd);named=os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False)
        for value in (opened,named):
            if (not stat.S_ISDIR(value.st_mode) or (value.st_dev,value.st_ino)!=self.identity
                or (value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode))!=(self.uid,self.gid,0o700)):
                raise ValueError('captured ACK generation replaced')

    def _socket(self,name):
        value=os.stat(name,dir_fd=self.directory_fd,follow_symlinks=False)
        if (not stat.S_ISSOCK(value.st_mode) or (value.st_dev,value.st_ino)!=self.sockets[name]
            or (value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode),value.st_nlink)!=(self.uid,self.gid,0o600,1)):
            raise ValueError('captured ACK socket replaced')

    def _inspect_sockets(self):
        names=set()
        with os.scandir(self.directory_fd) as entries:
            for entry in entries:
                if entry.name not in self.sockets:raise ValueError('unexpected generation ACK content')
                self._socket(entry.name)
                names.add(entry.name)
        return names

    def absent(self):
        """Read-only confirmation that normal producer deinit removed its path."""
        if self.state!='captured':return self.state=='absent'
        self._parent()
        try:os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False)
        except FileNotFoundError:
            self.close();self.state='absent';return True
        return False

    def remove_after_exit(self,watch):
        if self.state!='captured':raise ValueError('one live captured path receipt required')
        producer=self.enrollment.producer
        if (not isinstance(watch,ProcessLifetimeWatch) or watch.pid!=producer.pid
            or watch.lifetime_id!=producer.process_start_id or watch.alive() or watch.state!='exited'):
            raise ValueError('captured native producer must have a confirmed exit')
        self.state='retiring'
        try:
            self._directory()
            # An exited producer can have removed part of its own generation.
            # Validate the entire surviving set before unlinking any endpoint.
            for name in self._inspect_sockets():
                self._socket(name)
                os.unlink(name,dir_fd=self.directory_fd)
            self._directory()
            if os.listdir(self.directory_fd):raise ValueError('generation ACK content appeared')
            os.rmdir(self.name,dir_fd=self.parent_fd);os.fsync(self.parent_fd)
            self.result={'owned_directory_removed':True,'inspection_required':False}
            self.close();self.state='removed';return dict(self.result)
        except Exception:
            self.result={'owned_directory_removed':False,'inspection_required':True}
            self.close();self.state='uncertain';raise

    def close(self):
        for name in ('directory_fd','parent_fd'):
            fd=getattr(self,name)
            if fd is not None:os.close(fd);setattr(self,name,None)
        self.state='closed'


class ReplyWriterPump:
    MAX_DATAGRAMS=64
    BUDGET_SECONDS=.002

    def __init__(self,endpoint,session,destination,*,assembler=None):
        if not isinstance(endpoint,ReplyEndpoint) or not endpoint.healthy():raise ValueError('healthy owned helper endpoint required')
        if not isinstance(session,ReplyWriterSession) or session.state!='ready' or not session._healthy():
            raise ValueError('qualified guarded writer session required')
        if not isinstance(destination,ReplyDestination) or not destination.healthy():raise ValueError('pinned producer ACK destination required')
        if assembler is not None and not isinstance(assembler,ipc.MessageAssembler):raise ValueError('owned startup assembler required')
        self.endpoint,self.session,self.destination=endpoint,session,destination
        self.assembler=ipc.MessageAssembler() if assembler is None else assembler
        self.counters={name:0 for name in ('datagrams','replies','rejected','acks','budget_yields','late_acks')}
        self.state='ready';self.reason=None;self.drained=False
        ipc.configure_receiver(endpoint.socket);ipc.configure_sender(endpoint.socket)
        session.finish_startup()

    def _stop(self,reason):
        if self.reason is None:self.reason=reason
        self.state='suspended';self.drained=False;self.session._suspend(reason)

    def _healthy(self):
        if self.state!='ready':return False
        if not self.endpoint.healthy() or not self.destination.healthy():self._stop('reply_endpoint_changed')
        elif not self.session._healthy():self._stop(self.session.reason or 'writer_unavailable')
        return self.state=='ready'

    def _count(self,key):self.counters[key]=min(2**63-1,self.counters[key]+1)

    def poll(self):
        """At most64 nonblocking datagrams and a2ms soft budget between events.

        A single writer step retains its original40ms request budget. Results
        are ACK outcomes, not firewall pass/block decisions or DNS delivery.
        No storage or telemetry serialization is performed on this path.
        """
        self.drained=False;outcomes=[];started=time.monotonic()
        if not self._healthy():return outcomes
        try:self.assembler.advance(started)
        except ipc.RejectedMessage:self._stop('reply_fragment_clock');return outcomes
        if self.assembler.discarded:self._stop('reply_fragment_gap');return outcomes
        producer=self.session.guard.producer
        for unused in range(self.MAX_DATAGRAMS):
            if time.monotonic()-started>=self.BUDGET_SECONDS:
                self._count('budget_yields')
                # A single valid reply may consume the batch budget. Observe
                # readiness without consuming another event so periodic table
                # audits can run between queries instead of starving under a
                # steady low-rate workload. Partial fragments are never empty.
                try:
                    self.drained=not self.assembler.pending and not select.select([self.endpoint.socket],[],[],0)[0]
                except (OSError,ValueError):self._stop('reply_readiness_failed')
                break
            try:
                event,cred=ipc.receive(self.endpoint.socket,expected_uid=producer.uid,expected_pid=producer.pid,assembler=self.assembler)
            except ipc.IncompleteMessage:
                self._count('datagrams')
                if self.assembler.discarded:self._stop('reply_fragment_gap');break
                continue
            except BlockingIOError:
                self.drained=not self.assembler.pending
                break
            except InterruptedError:continue
            except ipc.RejectedMessage:self._count('rejected');continue
            except OSError:self._stop('reply_receive_failed');break
            self._count('datagrams');self._count('replies')
            if self.assembler.discarded:self._stop('reply_fragment_gap');break
            result=self.session.process(event,cred);ack=result['ack']
            if ack is None:continue
            # A suspended session may send one bounded helper_error to release
            # its current callback. It can never send another success ACK.
            if ack['status'] in ('applied','ignored') and not self.session._healthy():
                self._stop(self.session.reason or 'writer_unavailable');break
            synchronized=time.monotonic()
            try:
                deadline=result.get('send_before',event['monotonic']+self.session.budget)
                sent=self.destination.send(self.endpoint,ack,deadline=deadline)
            except (OSError,ValueError,KeyError,TypeError):sent='ack_send_failed'
            # Return the already-bounded input for optional off-path telemetry;
            # this component neither persists it nor infers HTTP delivery.
            outcomes.append(result|{'ack_transport':sent,'observation':event,'synchronized_monotonic':synchronized})
            if sent!='queued':
                if sent=='deadline' and getattr(self.session,'tolerate_late',False) is True and self.session._healthy():
                    self._count('late_acks');continue
                self._stop('reply_endpoint_changed' if sent=='endpoint_changed' else 'reply_ack_'+sent);break
            self._count('acks')
            if self.session.state!='ready':self._stop(self.session.reason or 'writer_unavailable');break
        else:self._count('budget_yields')
        return outcomes

    def status(self):
        value={'state':self.state,'reason':self.reason,'counters':dict(self.counters),
            'pending_fragments':len(self.assembler.pending),'pending_bytes':self.assembler.bytes,
            'queue_observed_drained':self.drained,
            'independent_cleanup_required':self.state!='ready','production_enforcement_qualified':False}
        if self.reason=='reply_endpoint_changed':
            value['endpoint_failure']={'helper':self.endpoint.status(),'ack_destination':self.destination.status()}
        return value
