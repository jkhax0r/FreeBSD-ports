"""Inactive standalone observation callback, embedded by hookbuild.

The builder supplies a fixed validated configuration and bounded scalar/sender
functions. No environment configuration, files, PF writes, reply changes,
background workers or synchronous acknowledgement. Loss is cumulative and
explicit; this feed cannot be used to authorize an enforcement update.
"""
import socket
import time
import uuid

_socket = None
_module_id = None
_generation = None
_generation_started = None
_drops = 0
_tokens = 0
_last_token_time = None


def _drop():
    global _drops
    _drops = min(2**63-1, _drops+1)


def _permit(now):
    global _tokens, _last_token_time
    if now < _last_token_time:
        _drop()
        return False
    _tokens = min(_dnsalias_observer_config['burst'],
                  _tokens + (now-_last_token_time)*_dnsalias_observer_config['max_events_per_second'])
    _last_token_time = now
    if _tokens < 1:
        _drop()
        return False
    _tokens -= 1
    return True


def snapshot(kind, qinfo, qstate, rep, rcode, edns, opt_list_out, region, **kwargs):
    try:
        mono = time.monotonic()
        # Sampling belongs to the passive observer. A qualified synchronous
        # alias wrapper already has bounded messages, an ACK deadline, fixed
        # resolver workers and bounded receiver/telemetry queues. Sampling its
        # required mappings would manufacture a fatal gap during a short burst.
        if not _dnsalias_observer_config.get('synchronous_mapping',False) and not _permit(mono): return True
        q = qinfo if qinfo is not None else qstate.qinfo
        peer = kwargs.get('repinfo')
        blocked = bypass = False
        if _dnsalias_observer_config['policy_mode'] == 'pfblockerng':
            context = dnsalias_policy_context
            config = context['pfb']
            client = str(peer.addr) if peer is not None else None
            bypass = bool(config.get('gpListDB') and client in context['gpListDB'])
            blocked = bool(config.get('python_enable') and not bypass
                           and q.qname_str.rstrip('.').lower() in context['dnsblDB'])
        event = _dnsalias_extract_reply(kind, qinfo, qstate, rep, rcode,
            peer=peer, callback_start_time=kwargs.get('start_time'),
            module_id=_module_id, finished_state=MODULE_FINISHED,
            observed_utc=time.time(), observed_monotonic=mono,
            resolver_generation=_generation, generation_started_monotonic=_generation_started,
            profile_id=_dnsalias_observer_config['profile_id'], unbound_version='1.26.1',
            policy_block_registry_match=blocked, policy_bypass_client=bypass)
        event['transport_dropped_before'] = _drops
        if _dnsalias_send_observation(_socket, _dnsalias_observer_config['destination'], event) != 'queued':
            _drop()
    except Exception:
        # Do not turn a missing field, oversize reply or socket outage into a
        # DNS failure or an unbounded log stream. The next event reports loss.
        _drop()
    return True


def resolved(*args, **kwargs): return snapshot('resolved', *args, **kwargs)
def cached(*args, **kwargs): return snapshot('cache', *args, **kwargs)
def local(*args, **kwargs): return snapshot('local', *args, **kwargs)
def failed(*args, **kwargs): return snapshot('servfail', *args, **kwargs)


def init_standard(module_id, env):
    global _socket, _module_id, _generation, _generation_started, _tokens, _last_token_time, _drops
    _module_id = module_id
    _generation = uuid.uuid4().hex
    _generation_started = _last_token_time = time.monotonic()
    _tokens = _dnsalias_observer_config['burst']
    _drops = 0
    if _dnsalias_observer_config['policy_mode'] == 'pfblockerng':
        if not isinstance(dnsalias_policy_context.get('pfb'), dict):
            raise ValueError('qualified policy context missing')
        for key in ('dnsblDB', 'gpListDB'):
            if key not in dnsalias_policy_context: raise ValueError('qualified policy registry missing')
    if _socket is not None: _socket.close()
    _socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    _dnsalias_configure_sender(_socket)
    for register, callback in ((register_inplace_cb_reply, resolved),
            (register_inplace_cb_reply_cache, cached), (register_inplace_cb_reply_local, local),
            (register_inplace_cb_reply_servfail, failed)):
        if not register(callback, env, module_id): return False
    return True


def deinit(module_id):
    global _socket
    if _socket is not None: _socket.close()
    _socket = None
    return True
