"""Compose an optional existing policy hook with an observation-only hook.

This module is not activated by the observer installer. Callers must verify
trusted source files and lifecycle ownership before production integration.
"""


def runtime_api(namespace):
    """Capture the fixed Unbound API, never a snapshot of shared policy data.

    Unbound reloads the script in the same module. Policy initialization can
    replace large dictionaries after this builder runs; copying globals here
    would keep their previous values alive throughout the next generation.
    """
    return {name:namespace[name] for name in (
        'MODULE_EVENT_NEW','MODULE_EVENT_PASS','MODULE_EVENT_MODDONE',
        'MODULE_WAIT_MODULE','MODULE_FINISHED','MODULE_ERROR',
        'register_inplace_cb_reply','register_inplace_cb_reply_cache',
        'register_inplace_cb_reply_local','register_inplace_cb_reply_servfail',
        'log_err','log_info') if name in namespace}


def compose(api, observer_source, policy_source=None, *, existing_policy=None):
    if policy_source is not None and existing_policy is not None:
        raise ValueError('choose one policy source')
    has_policy=policy_source is not None or existing_policy is not None
    # Every captured namespace is owned. Unbound reuses __main__ across loads,
    # and native callback references can outlive deinit. A retired callback
    # must not retain copies of a multi-million-entry policy dictionary.
    api=dict(api)
    policy, observer = dict(api), dict(api)
    if existing_policy is not None:
        policy={name:existing_policy[name] for name in
                ('init_standard','deinit','operate','inform_super')}
    if policy_source is not None:
        exec(compile(policy_source,"existing_policy_hook","exec"),policy)
    if has_policy:
        # Existing functions may retain the original module globals even when
        # their entry-point references were copied into an overlay namespace.
        observer['dnsalias_policy_context']=getattr(policy.get('operate'),'__globals__',policy)
    health={"observer_loaded":False,"observer_initialized":False,"observer_error":None}
    attempted=False;retired=False

    def observer_error(exc):
        health["observer_initialized"]=False
        first=health["observer_error"] is None
        health["observer_error"]=type(exc).__name__+": "+str(exc)[:160]
        if first and "log_err" in api:
            try: api["log_err"]("DNS Alias observation disabled: "+health["observer_error"])
            except Exception: pass

    # Only the observer registrations receive this guard. Existing policy
    # callbacks keep their return values and exception behavior unchanged.
    def guarded_register(register):
        def register_observer(callback, *args, **kwargs):
            def guarded(*cb_args, **cb_kwargs):
                if health["observer_initialized"]:
                    try:
                        if callback(*cb_args, **cb_kwargs) is False:
                            observer_error(RuntimeError("observer callback returned false"))
                    except Exception as exc: observer_error(exc)
                return True
            return register(guarded, *args, **kwargs)
        return register_observer

    for name in ("register_inplace_cb_reply", "register_inplace_cb_reply_cache",
                 "register_inplace_cb_reply_local", "register_inplace_cb_reply_servfail"):
        if name in api: observer[name]=guarded_register(api[name])
    try:
        exec(compile(observer_source,"dnsalias_observer_hook","exec"),observer)
        health["observer_loaded"]=True
    except Exception as exc: observer_error(exc)

    def init_standard(module_id,env):
        nonlocal attempted
        if retired:return False
        if has_policy:
            if policy["init_standard"](module_id,env) is False:
                return False
        if health["observer_loaded"]:
            try:
                attempted=True
                health["observer_initialized"]=observer["init_standard"](module_id,env) is not False
                if not health["observer_initialized"]: observer_error(RuntimeError("observer initialization failed"))
            except Exception as exc:
                observer_error(exc)
        return True

    def deinit(module_id):
        nonlocal retired
        if retired:return True
        try:
            try:
                health["observer_initialized"]=False
                if attempted and "deinit" in observer: observer["deinit"](module_id)
            except Exception as exc: observer_error(exc)
            return policy["deinit"](module_id) if has_policy else True
        finally:
            # Never clear the vendor's actual module globals or the caller's
            # API dictionary. Clear only our copies after its deinit returns
            # (or raises), leaving registered wrappers inert and lightweight.
            retired=True;health['observer_loaded']=False;health['retired']=True
            observer.clear();policy.clear();api.clear()

    def operate(module_id,event,qstate,qdata):
        if retired:raise RuntimeError('DNS Alias dispatcher retired')
        if has_policy:
            return policy["operate"](module_id,event,qstate,qdata)
        if event in (api["MODULE_EVENT_NEW"],api["MODULE_EVENT_PASS"]):
            qstate.ext_state[module_id]=api["MODULE_WAIT_MODULE"]
        elif event==api["MODULE_EVENT_MODDONE"]:
            qstate.ext_state[module_id]=api["MODULE_FINISHED"]
        else:
            qstate.ext_state[module_id]=api["MODULE_ERROR"]
        return True

    def inform_super(module_id,qstate,superqstate,qdata):
        if retired:raise RuntimeError('DNS Alias dispatcher retired')
        return policy["inform_super"](module_id,qstate,superqstate,qdata) if has_policy else True

    return {"init_standard":init_standard,"deinit":deinit,"operate":operate,"inform_super":inform_super,
            "dnsalias_observer_health":health}
