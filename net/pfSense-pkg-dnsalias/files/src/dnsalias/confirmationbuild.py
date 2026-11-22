"""Pure optional resolver startup assembly; no service enrollment or I/O."""
import ast
from .confirmationpage import contract as page_contract
from .nativewire import contract as native_contract

COMPONENTS=('page','process_watch','key','gate','transport')
IMPORTS={'confirmationkey':{'confirmation_key','key_with_loss_counter','scope_reply_keys'},'ipc':{'RejectedMessage','receive','send_observation'},
         'replygate':{'ReplyGate','RejectedEpoch','clock'}}


def render(*,native,page,sources,helper_pid,native_key=None,notice=None,refresh=False,retirement=None):
    if type(refresh) is not bool or (refresh and (notice is None or notice.get('source_watches')!=1)):
        raise ValueError('explicit complete source-watch refresh required')
    native=native_contract(native);page=page_contract(page)
    if page['writer_pid']!=helper_pid:raise ValueError('page publisher must be the enrolled ACK helper')
    names=COMPONENTS+(('change_barrier','watch_transfer','watch_startup') if notice is not None else ())
    if refresh:names+=('refresh',)
    if type(sources) is not dict or set(sources)!=set(names):raise ValueError('complete confirmation sources required')
    inputs={};pieces=[]
    for name in COMPONENTS:
        source=sources[name]
        if type(source) is not str or not 1<=len(source.encode())<=65536:raise ValueError('bounded confirmation source required')
        tree=ast.parse(source);relative=[n for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.level]
        if name=='transport':
            if (len(relative)!=len(IMPORTS) or {n.module for n in relative}!=set(IMPORTS)
                or any(n not in tree.body or n.level!=1 or {x.name for x in n.names}!=IMPORTS[n.module]
                       or any(x.asname for x in n.names) for n in relative)):
                raise ValueError('qualified confirmation transport imports required')
        elif relative:raise ValueError('standalone confirmation component required')
        lines=source.splitlines(keepends=True)
        for node in sorted(relative,key=lambda n:n.lineno,reverse=True):lines[node.lineno-1:node.end_lineno]=['\n']
        inputs['confirmation_'+name+'_source']=source
        pieces.append('exec('+repr(''.join(lines))+',_dnsalias_confirmation_scope)\n')
    code=('_dnsalias_confirmation_scope={name:_dnsalias_ack_ipc_scope[name] '
          'for name in ("RejectedMessage","receive","send_observation")}\n'+''.join(pieces)+STARTUP)
    config={'native':native,'page':page}
    if notice is not None:
        from .watchstartup import contract as notice_contract
        notice=notice_contract(notice)
    if retirement is not None:
        import re
        if (notice is None or type(retirement) is not dict or set(retirement)!={'path','token'}
            or type(retirement['path']) is not str or not re.fullmatch(r'/[A-Za-z0-9_./-]+',retirement['path'])
            or any(p in ('','.','..') for p in retirement['path'].split('/')[1:]) or len(retirement['path'].encode())>103
            or type(retirement['token']) is not str or not re.fullmatch('[a-f0-9]{64}',retirement['token'])
            or retirement['token']=='0'*64 or retirement['path'] in (notice['donor'],notice['directory']+'/replies.sock')):
            raise ValueError('distinct owned reader lifecycle endpoint required')
        config['retirement']=dict(retirement)
    if refresh:config['refresh']=True
    if native_key is not None:config['native_key']=native_contract(native_key)
    if notice is not None:
        config['notice']=notice
        # These components have generic internal function names. Keep their
        # globals separate from the page and from each other after embedding.
        component_imports={
            'change_barrier':{},
            'watch_transfer':{'changebarrier':{'FileChangeBarrier','CapabilityChangeBarrier'},'ipc':{'HEADER','MAX_GROUPS','RejectedMessage','parse_sockcred2','configure_sender'}},
            'watch_startup':{'watchtransfer':{'FilterWatchReceiver','SourceWatchReceiver'},'replyendpoint':{'ReplyEndpoint'},'ipc':{'receive','send_observation'}},
            'refresh':{'confirmationtransport':{'ConfirmationTransport'},'watchstartup':{'FilterWatchEnrollment'}}}
        scopes={
            'change_barrier':'{}',
            'watch_transfer':'dict(_dnsalias_ack_ipc_scope,FileChangeBarrier=_dnsalias_change_barrier_scope["FileChangeBarrier"],CapabilityChangeBarrier=_dnsalias_change_barrier_scope["CapabilityChangeBarrier"])',
            'watch_startup':'dict(_dnsalias_ack_ipc_scope,FilterWatchReceiver=_dnsalias_watch_transfer_scope["FilterWatchReceiver"],SourceWatchReceiver=_dnsalias_watch_transfer_scope["SourceWatchReceiver"],ReplyEndpoint=_dnsalias_endpoint_scope["ReplyEndpoint"])',
            'refresh':'dict(ConfirmationTransport=_dnsalias_confirmation_scope["ConfirmationTransport"],FilterWatchEnrollment=_dnsalias_watch_startup_scope["FilterWatchEnrollment"])'}
        added=[];late=[]
        for name in names[len(COMPONENTS):]:
            source=sources[name]
            if type(source) is not str or not 1<=len(source.encode())<=65536:raise ValueError('bounded watch source required')
            tree=ast.parse(source);relative=[n for n in ast.walk(tree) if isinstance(n,ast.ImportFrom) and n.level]
            expected=component_imports[name]
            if (len(relative)!=len(expected) or {n.module for n in relative}!=set(expected)
                or any(n not in tree.body or n.level!=1 or {x.name for x in n.names}!=expected[n.module]
                    or any(x.asname for x in n.names) for n in relative)):
                raise ValueError('qualified watch component imports required')
            lines=source.splitlines(keepends=True)
            for node in sorted(relative,key=lambda n:n.lineno,reverse=True):lines[node.lineno-1:node.end_lineno]=['\n']
            inputs['confirmation_'+name+'_source']=source
            scope='_dnsalias_'+name+'_scope'
            (late if name=='refresh' else added).append(scope+'='+scopes[name]+'\nexec('+repr(''.join(lines))+','+scope+')\n')
        code=''.join(added)+code+''.join(late)
    return code,config,inputs


STARTUP=r'''
_dnsalias_confirmation_mapping=None
_dnsalias_confirmation_watch=None
_dnsalias_confirmation_transport=None
_dnsalias_confirmation_notice=None
_dnsalias_confirmation_failure=None

def _dnsalias_reader_notice(kind,candidate=None):
    # Deinit/startup only. No additional work is performed on DNS replies.
    value=_dnsalias_ack_config['confirmation'].get('retirement')
    if value is None:return False
    try:
        import socket as _retire_socket,time as _retire_time
        event=({'kind':kind,'token':value['token'],'profile_id':_dnsalias_observer_config['profile_id'],
            'resolver_generation':_generation,'generation_started_monotonic':_generation_started}
            if candidate is None else dict(candidate))
        event['observed_monotonic']=_retire_time.monotonic()
        with _retire_socket.socket(_retire_socket.AF_UNIX,_retire_socket.SOCK_DGRAM) as sender:
            _dnsalias_configure_sender(sender)
            return _dnsalias_ack_ipc_scope['send_observation'](sender,value['path'],event)=='queued'
    except Exception:return False  # No retry and no inferred retirement.

def _dnsalias_confirmation_retirement_candidate():
    try:
        value=_dnsalias_ack_config['confirmation'].get('retirement')
        transport=_dnsalias_confirmation_transport
        if value is None or transport is None or _dnsalias_confirmation_watch is None or not _dnsalias_confirmation_watch.alive():return None
        status=transport.status();refresh=status.get('refresh',{})
        notice=getattr(transport,'notice',_dnsalias_confirmation_notice)
        if notice is None:return None
        if status['state']=='ready' and not refresh.get('pending') and not refresh.get('failure') and notice.unchanged():
            kind='reader_retired'
        elif (status['state']=='ready' or status.get('reason')=='source_or_reload_changed') and not notice.unchanged():
            # Authorizes only a request to verify a config timestamp renewal.
            # deinit still must finish closing the reader and its owned socket.
            kind='reader_retired_config_check'
        else:return None
        return {'kind':kind,'token':value['token'],'profile_id':_dnsalias_observer_config['profile_id'],
            'resolver_generation':_generation,'generation_started_monotonic':_generation_started}
    except Exception:return None

def _dnsalias_confirmation_close():
    global _dnsalias_confirmation_mapping,_dnsalias_confirmation_watch,_dnsalias_confirmation_transport,_dnsalias_confirmation_notice
    mapping,_dnsalias_confirmation_mapping=_dnsalias_confirmation_mapping,None
    watch,_dnsalias_confirmation_watch=_dnsalias_confirmation_watch,None
    transport,_dnsalias_confirmation_transport=_dnsalias_confirmation_transport,None
    notice,_dnsalias_confirmation_notice=_dnsalias_confirmation_notice,None
    try:
        if transport is not None:transport.close()
    finally:
        try:
            if mapping is not None:mapping.close()
        finally:
            try:
                if watch is not None:watch.close()
            finally:
                if notice is not None:notice.close()
    return True

def _dnsalias_confirmation_start():
    global _dnsalias_confirmation_mapping,_dnsalias_confirmation_watch,_dnsalias_confirmation_transport,_dnsalias_confirmation_notice,_dnsalias_confirmation_failure
    if any(x is not None for x in (_dnsalias_confirmation_mapping,_dnsalias_confirmation_watch,_dnsalias_confirmation_transport,_dnsalias_confirmation_notice)):
        raise RuntimeError('Previous confirmation reader has not been retired')
    _dnsalias_confirmation_failure=None
    value=_dnsalias_ack_config['confirmation']
    native=_dnsalias_native_scope['load'](value['native'],'confirmation')
    key=None
    if value.get('native_key') is not None:
        key=_dnsalias_native_scope['load'](value['native_key'],'key').key
    try:
        watch=_dnsalias_confirmation_scope['ProcessLifetimeWatch'](_dnsalias_ack_config['helper_pid'])
        _dnsalias_confirmation_watch=watch
        mapping=_dnsalias_confirmation_scope['ConfirmationMapping'].open(native,value['page'],role='reader')
        _dnsalias_confirmation_mapping=mapping
        if not watch.alive():raise ValueError('Helper lifetime ended during confirmation enrollment')
        if value.get('retirement') is not None:_dnsalias_reader_notice('reader_hello')
        options={}
        if value.get('notice') is not None:
            try:
                watch_options={'native_watch':native} if value['notice'].get('source_watches') else {}
                notice=_dnsalias_watch_startup_scope['FilterWatchEnrollment'](value['notice'],
                    helper_pid=_dnsalias_ack_config['helper_pid'],profile_id=_dnsalias_observer_config['profile_id'],generation=_generation,**watch_options)
                _dnsalias_confirmation_notice=notice
                if not watch.alive() or not notice.unchanged():raise ValueError('Watch or helper changed during startup')
                options['unchanged']=notice.unchanged
            except Exception as exc:
                _dnsalias_confirmation_failure='watch_enrollment_failed:'+type(exc).__name__
                _dnsalias_confirmation_close()
                return None  # Optional acceleration failed; retain the ordinary ACK path.
        transport=_dnsalias_confirmation_scope['ConfirmationTransport'](
            helper_pid=_dnsalias_ack_config['helper_pid'],profile_id=_dnsalias_observer_config['profile_id'],
            generation=_generation,started=_generation_started,
            lookup=lambda digest:mapping.native.lookup(mapping.handle,digest),alive=watch.alive,key=key,
            scope_absent=lambda keys:mapping.native.scope_absent(mapping.handle,keys),
            socket_count=_dnsalias_ack_config.get('socket_count',1),**options)
        if value.get('refresh'):
            transport=_dnsalias_refresh_scope['RefreshingTransport'](transport,notice,native_watch=native)
        _dnsalias_confirmation_transport=transport
        return transport
    except BaseException:
        _dnsalias_confirmation_close()
        raise
'''
