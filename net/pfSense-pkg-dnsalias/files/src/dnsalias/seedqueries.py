"""Bounded nonblocking loopback queries; never a source of table membership.

One owner loop polls at most16 connected UDP sockets. No thread, subprocess,
periodic refresh, external endpoint, DNS retry or IP authorization. Actual
resolver replies must still traverse the separately authenticated trusted hook.
Cancellation closes local query sockets; it cannot unsend an already sent query.
"""
import math
import secrets
import select
import socket
import struct
import time

from .dnscheck import _question,parse,MAX_BYTES


class SeedQueries:
    def __init__(self,names,port,*,budget_seconds=2,cancel_requested=None):
        if (type(names) not in (tuple,list) or not 1<=len(names)<=8
            or any(type(n) is not str for n in names) or len(set(names))!=len(names)):
            raise ValueError('one to eight distinct seed names or suffixes required')
        if type(port) is not int or not 1<=port<=65535:raise ValueError('explicit loopback DNS port required')
        if (type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds)
            or not .05<=budget_seconds<=2):raise ValueError('bounded fixed seed budget required')
        if cancel_requested is not None and not callable(cancel_requested):raise ValueError('optional cancellation probe required')
        questions=[]
        # Validate the complete input before opening or sending anything.
        for name in names:
            if name.startswith('*.'):_question(name[2:],1);continue
            for kind in (1,28):
                canonical,question=_question(name,kind);questions.append((canonical,kind,question))
        self.started=time.monotonic()
        if not math.isfinite(self.started) or self.started<0:raise ValueError('qualified seed clock required')
        self.deadline=self.started+budget_seconds;self.cancel_requested=cancel_requested
        self.pending={};self.done=False
        self.counts={'attempted':0,'answered':0,'failed':0,'cancelled_queries':0,'cancelled':False,
            'budget_exhausted':False,'direct_membership_writes':False,'periodic_refresh':False,
            'background_thread':False,'nonblocking':True}
        if self._cancelled():self.close(cancelled=True);return
        for canonical,kind,question in questions:
            self.counts['attempted']+=1;client=None
            try:
                ident=secrets.randbelow(65536);packet=struct.pack('!6H',ident,0x100,1,0,0,0)+question
                client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.setblocking(False)
                client.connect(('127.0.0.1',port))
                if client.send(packet)!=len(packet):raise OSError('short seed datagram')
                self.pending[client]=(ident,canonical,kind)
            except OSError:
                self.counts['failed']+=1
                if client is not None:client.close()
        self.done=not self.pending

    def _cancelled(self):
        value=False if self.cancel_requested is None else self.cancel_requested()
        if type(value) is not bool:raise ValueError('explicit boolean seed cancellation required')
        return value

    def readers(self):return tuple(self.pending)

    def poll(self):
        if self.done:return self.status()
        if self._cancelled():self.close(cancelled=True);return self.status()
        now=time.monotonic()
        if not math.isfinite(now) or now<self.started:
            self.close(cancelled=True);raise ValueError('seed clock regressed')
        if now>=self.deadline:
            self.counts['budget_exhausted']=True;self.counts['failed']+=len(self.pending)
            self._close_pending();return self.status()
        # Read-ready sockets only; never wait inside the supervising owner loop.
        ready,_,_=select.select(self.readers(),[],[],0)
        for client in ready:
            ident,name,kind=self.pending[client]
            try:
                raw=client.recv(MAX_BYTES+1)
                parse(raw,ident=ident,name=name,kind=kind)
            except BlockingIOError:continue
            except (OSError,ValueError):self.counts['failed']+=1
            else:self.counts['answered']+=1
            client.close();del self.pending[client]
        self.done=not self.pending
        return self.status()

    def _close_pending(self):
        for client in self.pending:client.close()
        self.pending.clear();self.done=True

    def close(self,*,cancelled=False):
        if type(cancelled) is not bool:raise ValueError('explicit seed cancellation state required')
        if self.done:return
        self.counts['cancelled']=cancelled
        self.counts['cancelled_queries']+=len(self.pending)
        self._close_pending()

    def status(self):return dict(self.counts)|{'pending':len(self.pending),'complete':self.done}
