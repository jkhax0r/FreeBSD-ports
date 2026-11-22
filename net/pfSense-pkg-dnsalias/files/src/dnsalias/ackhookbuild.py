"""Pure self-contained ACK companion builder; no installed hook or activation.

Its returned companion source is the observer_source that must be persisted and
source-audited before computing a deployment profile. It binds every embedded
component and fixed ACK setting, including the helper PID. Feed it through the
existing render_observer and plain/pfBlockerNG dispatcher builders. No external
package import is needed inside the Unbound chroot.
"""
import ast
import hashlib
import math
import re
from .nativewire import contract as validate_native_contract
from .hookbuild import MAX_OBSERVER_SOURCE_BYTES
from .replyendpoint import ack_socket_names


def _local_source(source,imports):
    if type(source) is not str or not 1<=len(source.encode())<=65536:
        raise ValueError('bounded inspected component source required')
    tree=ast.parse(source);relative=[n for n in tree.body if isinstance(n,ast.ImportFrom) and n.level]
    if len(relative)!=1 or relative[0].level!=1 or relative[0].module!='ipc' or {n.name for n in relative[0].names}!=set(imports) or any(n.asname for n in relative[0].names):
        raise ValueError('qualified embedded IPC import contract required')
    node=relative[0];lines=source.splitlines(keepends=True)
    lines[node.lineno-1:node.end_lineno]=['\n']
    return ''.join(lines)


def companion(*,observer_source,transport_source,acknowledger_source,endpoint_source,
              helper_pid,reply_directory,timeout=.05,cooldown=.5,per_generation=False,socket_count=1,
              native_contract=None,native_loader_source=None,native_extract_contract=None,native_generation_contract=None,
              native_confirmation_contract=None,confirmation_page=None,confirmation_sources=None,native_key_contract=None,confirmation_notice=None,confirmation_refresh=False,confirmation_retirement=None):
    if type(helper_pid) is not int or not 0<helper_pid<2**31:
        raise ValueError('explicit enrolled helper PID required')
    if type(per_generation) is not bool:raise ValueError('explicit generation endpoint mode required')
    ack_socket_names(socket_count)
    if socket_count!=1 and not per_generation:raise ValueError('worker sockets require a generation')
    if (type(reply_directory) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]{1,88}',reply_directory)
        or any(p in ('','.','..') for p in reply_directory.split('/')[1:])
        or len((reply_directory+('/g-'+'0'*32 if per_generation else '')+'/replies.sock').encode())>103):
        raise ValueError('short canonical owned ACK directory required')
    for value,minimum,maximum in ((timeout,0,.1),(cooldown,.1,5)):
        if type(value) not in (int,float) or not math.isfinite(value) or not minimum<=value<=maximum or value<=0:
            raise ValueError('bounded ACK timeout/cooldown required')
    inputs={'observer_source':observer_source,'transport_source':transport_source,
            'acknowledger_source':acknowledger_source,'endpoint_source':endpoint_source}
    for body in inputs.values():
        if type(body) is not str or not 1<=len(body.encode())<=65536:raise ValueError('bounded source text required')
        ast.parse(body)
    ack=_local_source(acknowledger_source,('RejectedMessage','receive','send_observation'))
    endpoint=_local_source(endpoint_source,('configure_receiver',))
    fixed={'helper_pid':helper_pid,'reply_directory':reply_directory,'timeout':timeout,'cooldown':cooldown}
    if per_generation:fixed['per_generation']=True
    if socket_count>1:fixed['socket_count']=socket_count
    native='';confirmation=''
    if any(v is not None for v in (native_confirmation_contract,confirmation_page,confirmation_sources,native_key_contract,confirmation_notice,confirmation_retirement)) or confirmation_refresh:
        if not per_generation:raise ValueError('confirmation reader requires generation endpoint')
        from .confirmationbuild import render
        confirmation,fixed['confirmation'],more=render(native=native_confirmation_contract,page=confirmation_page,
            sources=confirmation_sources,helper_pid=helper_pid,native_key=native_key_contract,notice=confirmation_notice,refresh=confirmation_refresh,retirement=confirmation_retirement)
        inputs.update(more)
    if any(v is not None for v in (native_contract,native_extract_contract,native_generation_contract,native_confirmation_contract,native_loader_source)):
        # Validate the descriptor without executing supplied source. The
        # independently audited loader text is embedded and hash-bound.
        if type(native_loader_source) is not str or not 1<=len(native_loader_source.encode())<=65536:
            raise ValueError('bounded pinned native loader source required')
        ast.parse(native_loader_source)
        if all(v is None for v in (native_contract,native_extract_contract,native_generation_contract,native_confirmation_contract)):raise ValueError('native descriptor required')
        inputs['native_loader_source']=native_loader_source
        if native_contract is not None:fixed['native_codec']=validate_native_contract(native_contract)
        if native_extract_contract is not None:fixed['native_extractor']=validate_native_contract(native_extract_contract)
        if native_generation_contract is not None:
            if not per_generation:raise ValueError('native checker requires generation endpoint')
            fixed['native_generation']=validate_native_contract(native_generation_contract)
        native=('_dnsalias_native_scope={}\nexec('+repr(native_loader_source)+',_dnsalias_native_scope)\n')
    source=('_dnsalias_ack_config='+repr(fixed)+'\n'
        '_dnsalias_ack_ipc_scope={}\nexec('+repr(transport_source)+',_dnsalias_ack_ipc_scope)\n'
        '_dnsalias_ack_scope={name:_dnsalias_ack_ipc_scope[name] for name in ("RejectedMessage","receive","send_observation")}\n'
        'exec('+repr(ack)+',_dnsalias_ack_scope)\n'
        '_dnsalias_endpoint_scope={"configure_receiver":_dnsalias_ack_ipc_scope["configure_receiver"]}\n'
        'exec('+repr(endpoint)+',_dnsalias_endpoint_scope)\n'
        '_dnsalias_ack_type=_dnsalias_ack_scope["ReplyAcknowledger"]\n'
        '_dnsalias_endpoint_type=_dnsalias_endpoint_scope["GenerationReplyEndpoint" if _dnsalias_ack_config.get("per_generation",False) else "ReplyEndpoint"]\n')+native+confirmation+observer_source+'\n'+WRAPPER
    if len(source.encode())>MAX_OBSERVER_SOURCE_BYTES:raise ValueError('bounded companion size required')
    ast.parse(source)
    return source,{'format':'dnsalias-ack-companion-1','fixed':fixed,
        'component_sha256':{name:hashlib.sha256(body.encode()).hexdigest() for name,body in inputs.items()},
        'observer_source_sha256':hashlib.sha256(source.encode()).hexdigest(),
        'dns_failure_policy':'preserve_original_reply','production_enforcement_qualified':False,
        'required_profile_binding':'Persist and audit this exact companion as observer_source before rendering its profile-bound hook.'}


WRAPPER=r'''
import threading as _dnsalias_threading

_dnsalias_base_init=init_standard
_dnsalias_base_deinit=deinit
_dnsalias_owned_ack=None
_dnsalias_ack_client=None
_dnsalias_ack_clients=()
_dnsalias_worker_slots={}
_dnsalias_worker_lock=_dnsalias_threading.Lock()
_dnsalias_python_extract_reply=_dnsalias_extract_reply
_dnsalias_native_extract_small=None

def _dnsalias_extract_with_fallback(*args,**kwargs):
    result=_dnsalias_native_extract_small(*args,**kwargs)
    return _dnsalias_python_extract_reply(*args,**kwargs) if result is None else result

def init_standard(module_id,env):
    global _socket,_dnsalias_owned_ack,_dnsalias_ack_client,_dnsalias_ack_clients
    global _dnsalias_extract_reply,_dnsalias_native_extract_small
    if _dnsalias_owned_ack is not None:
        raise RuntimeError('Previous ACK endpoint has not been retired')
    if _dnsalias_observer_config['destination']==_dnsalias_ack_config['reply_directory']+'/replies.sock':
        raise ValueError('Helper request and resolver reply sockets must differ')
    try:
        generation_check=None
        if _dnsalias_ack_config.get('native_generation') is not None:
            generation_check=_dnsalias_native_scope['load'](_dnsalias_ack_config['native_generation'],'generation').check
        if _dnsalias_ack_config.get('native_codec') is not None:
            codec=_dnsalias_native_scope['load'](_dnsalias_ack_config['native_codec'])
            _dnsalias_ack_ipc_scope['configure_native_wire'](codec)
        if _dnsalias_ack_config.get('native_extractor') is not None:
            extractor=_dnsalias_native_scope['load'](_dnsalias_ack_config['native_extractor'],'extract')
            _dnsalias_native_extract_small=extractor.extract_small
            _dnsalias_extract_reply=_dnsalias_extract_with_fallback
        if not _dnsalias_base_init(module_id,env):
            _dnsalias_base_deinit(module_id)
            return False
    except Exception:
        _dnsalias_base_deinit(module_id)
        raise
    original=_socket
    try:
        socket_count=_dnsalias_ack_config.get('socket_count',1)
        confirmation_options={}
        if _dnsalias_ack_config.get('confirmation') is not None:
            confirmation_options['confirmation']=_dnsalias_confirmation_start()
        if _dnsalias_ack_config.get('per_generation',False):
            options={} if generation_check is None else {'native_check':generation_check}
            if socket_count>1:options['socket_count']=socket_count
            _dnsalias_owned_ack=_dnsalias_endpoint_type(_dnsalias_ack_config['reply_directory'],
                generation=_generation,**options)
        else:
            _dnsalias_owned_ack=_dnsalias_endpoint_type(_dnsalias_ack_config['reply_directory'])
        _socket=_dnsalias_owned_ack.socket
        sockets=([endpoint.socket for endpoint in _dnsalias_owned_ack.endpoints]
                 if socket_count>1 else [_socket])
        clients=[]
        for slot,ack_socket in enumerate(sockets):
            _dnsalias_configure_sender(ack_socket)
            if socket_count>1:confirmation_options['slot']=slot
            clients.append(_dnsalias_ack_type(ack_socket,_dnsalias_observer_config['destination'],
                helper_pid=_dnsalias_ack_config['helper_pid'],timeout=_dnsalias_ack_config['timeout'],cooldown=_dnsalias_ack_config['cooldown'],
                **confirmation_options))
        _dnsalias_ack_clients=tuple(clients)
        _dnsalias_ack_client=clients[0]
        return True
    except Exception:
        # Preserve ambiguous/foreign paths; the endpoint owns exact cleanup.
        try:
            if _dnsalias_ack_config.get('confirmation') is not None:_dnsalias_confirmation_close()
        finally:
            if _dnsalias_owned_ack is not None:_dnsalias_owned_ack.close()
            _socket=None
        raise
    finally:
        original.close()

def _dnsalias_worker_slot():
    if len(_dnsalias_ack_clients)<=1:return 0
    worker=_dnsalias_threading.get_ident()
    slot=_dnsalias_worker_slots.get(worker)
    if slot is not None:return slot
    with _dnsalias_worker_lock:
        if len(_dnsalias_worker_slots)<len(_dnsalias_ack_clients):
            return _dnsalias_worker_slots.setdefault(worker,len(_dnsalias_worker_slots))
        # A larger configured resolver can share slot zero. Native callback
        # identity is used only for scheduling, never as authentication.
        return _dnsalias_worker_slots.get(worker,0)

def _dnsalias_send_observation(sock,destination,event):
    if (_dnsalias_owned_ack is None or _dnsalias_ack_client is None or
        sock is not _dnsalias_owned_ack.socket or destination!=_dnsalias_observer_config['destination']):
        return 'ack_endpoint_unavailable'
    slot=_dnsalias_worker_slot()
    healthy=_dnsalias_owned_ack.healthy(slot) if slot else _dnsalias_owned_ack.healthy()
    if not healthy:return 'ack_endpoint_unavailable'
    result=_dnsalias_ack_clients[slot].exchange(event)
    # Here queued means observation delivery, not successful PF membership.
    # The helper records helper_error separately in mapping/table statistics.
    # Treating its authenticated refusal as loss poisons every later callback.
    return 'queued' if result in ('applied','ignored','helper_error') else 'ack_'+result

def deinit(module_id):
    global _socket,_dnsalias_owned_ack,_dnsalias_ack_client,_dnsalias_ack_clients
    endpoint,_dnsalias_owned_ack=_dnsalias_owned_ack,None
    _dnsalias_ack_client=None
    _dnsalias_ack_clients=()
    _dnsalias_worker_slots.clear()
    retired=(_dnsalias_confirmation_retirement_candidate() if _dnsalias_ack_config.get('confirmation',{}).get('retirement') else None)
    reader_closed=False;endpoint_closed=None
    try:
        if _dnsalias_ack_config.get('confirmation') is not None:reader_closed=_dnsalias_confirmation_close()
    finally:
        if endpoint is not None:endpoint_closed=endpoint.close()
        _socket=None
    if (retired is not None and reader_closed is True and type(endpoint_closed) is dict
        and endpoint_closed.get('owned_directory_removed') is True and not endpoint_closed.get('inspection_required')):
        _dnsalias_reader_notice(retired['kind'],retired)
    return _dnsalias_base_deinit(module_id)
'''
