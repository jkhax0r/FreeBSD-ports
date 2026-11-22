"""Optional bounded startup handshake; no per-query socket or pathname work.

The root donor must run independently of the thread waiting for resolver load.
It sends the qualified FD, authenticates the enrolled reader's receipt, then
reconciles the named inode, sources and tables before sending the final commit.
The page must remain revoked until that reconciliation. This reader cannot
establish those owner-side conditions or recover a previous enrollment.
"""
import math
import re
import select
import time
from .watchtransfer import FilterWatchReceiver,SourceWatchReceiver
from .replyendpoint import ReplyEndpoint
from .ipc import receive,send_observation


def contract(value):
    fields={'directory','donor','token','identity','timeout'}
    if type(value) is not dict or set(value) not in (fields,fields|{'source_watches'}):
        raise ValueError('complete watch startup contract required')
    if 'source_watches' in value and (type(value['source_watches']) is not int or value['source_watches']!=1):
        raise ValueError('explicit source watch protocol required')
    for key in ('directory','donor'):
        path=value[key]
        if (type(path) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]+',path)
            or any(p in ('','.','..') for p in path.split('/')[1:])
            or len((path+('/replies.sock' if key=='directory' else '')).encode())>103):
            raise ValueError('short canonical watch endpoint required')
    if value['donor']==value['directory']+'/replies.sock':raise ValueError('distinct watch endpoints required')
    token=value['token'];identity=value['identity'];timeout=value['timeout']
    if type(token) is not str or not re.fullmatch('[a-f0-9]{64}',token) or token=='0'*64:
        raise ValueError('fresh watch enrollment token required')
    if (type(identity) not in (tuple,list) or len(identity)!=2 or any(type(x) is not int for x in identity)
        or not -(1<<63)<=identity[0]<(1<<64) or not 0<identity[1]<(1<<64)):
        raise ValueError('independently qualified watch inode required')
    if type(timeout) not in (int,float) or not math.isfinite(timeout) or not 0<timeout<=1:
        raise ValueError('startup-only bounded wait required')
    return dict(value,identity=tuple(identity))


class FilterWatchEnrollment:
    """One startup attempt; only a committed watch can reach the reply reader."""
    def __init__(self,value,*,helper_pid,profile_id,generation,native_watch=None,refresh_request=None):
        self.value=contract(value);self.watch=None;self.state='opening';self.reason=None
        self.manifest_digest=None
        if (type(profile_id) is not str or not re.fullmatch('[a-f0-9]{64}',profile_id)
            or type(generation) is not str or not re.fullmatch('[a-f0-9]{32}',generation)):
            raise ValueError('exact resolver profile and generation required')
        parameters=dict(helper_pid=helper_pid,token=bytes.fromhex(self.value['token']),identity=self.value['identity'])
        if self.value.get('source_watches'):
            if type(getattr(native_watch,'WATCH_FD_ABI',None)) is not int or native_watch.WATCH_FD_ABI!=1:
                raise ValueError('qualified native watch capability API required')
            receiver=SourceWatchReceiver(**parameters,check_rights=native_watch.watch_check)
        else:receiver=FilterWatchReceiver(**parameters)
        endpoint=None;deadline=time.monotonic()+self.value['timeout']
        try:
            endpoint=ReplyEndpoint(self.value['directory'])
            if refresh_request is not None:
                fields={'watch_refresh','nonce','sequence','profile_id','resolver_generation','source_manifest'}
                if (not self.value.get('source_watches') or type(refresh_request) is not dict
                    or set(refresh_request)!=fields or refresh_request['nonce']!=self.value['token']
                    or refresh_request['profile_id']!=profile_id or refresh_request['resolver_generation']!=generation
                    or type(refresh_request['sequence']) is not int or not 0<refresh_request['sequence']<2**31
                    or any(type(refresh_request[k]) is not str or not re.fullmatch('[a-f0-9]{64}',refresh_request[k])
                           for k in ('watch_refresh','source_manifest'))):
                    raise ValueError('complete fresh enrollment request required')
                if send_observation(endpoint.socket,self.value['donor'],refresh_request)!='queued':
                    raise ValueError('watch refresh request not sent; never retry')
            self._wait(endpoint.socket,deadline)
            self.watch=receiver.receive(endpoint.socket)
            if self.value.get('source_watches'):self.manifest_digest=receiver.manifest_digest
            if not self.watch.unchanged():raise ValueError('watch changed during enrollment')
            receipt={'watch_enrolled':self.value['token'],'profile_id':profile_id,'resolver_generation':generation}
            if self.value.get('source_watches'):receipt['source_manifest']=receiver.manifest_digest
            if send_observation(endpoint.socket,self.value['donor'],receipt)!='queued':
                raise ValueError('watch enrollment receipt not sent; never retry')
            self._wait(endpoint.socket,deadline)
            commit,_=receive(endpoint.socket,expected_uid=0,expected_pid=helper_pid)
            expected={'watch_committed':self.value['token'],'profile_id':profile_id,'resolver_generation':generation}
            if self.value.get('source_watches'):expected['source_manifest']=receiver.manifest_digest
            if commit!=expected or time.monotonic()>=deadline or not self.watch.unchanged() or not endpoint.healthy():
                raise ValueError('watch enrollment commit unqualified')
            self.state='ready'
        except BaseException:
            self.close();raise
        finally:
            if endpoint is not None:
                result=endpoint.close()
                if not result['owned_path_removed']:
                    self.close()
                    raise ValueError('watch endpoint cleanup requires inspection')

    @staticmethod
    def _wait(sock,deadline):
        remaining=deadline-time.monotonic()
        if remaining<=0 or not select.select([sock],[],[],remaining)[0]:
            raise TimeoutError('watch startup enrollment timed out; never retry')

    def unchanged(self):
        # The startup socket is already closed. This is only the pinned kqueue.
        if self.state!='ready':return False
        if self.watch.unchanged():return True
        self.reason=self.watch.reason;self.state='changed';return False

    def close(self):
        self.state='closed'
        if self.watch is not None:self.watch.close()
