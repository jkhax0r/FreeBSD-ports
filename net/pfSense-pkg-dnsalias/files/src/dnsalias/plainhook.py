# DNS Alias owned passthrough base v1.
# Unbound supplies the MODULE_* globals. The observation dispatcher composes
# onto this base; the base itself makes no DNS, file, table or policy decision.

def init_standard(module_id, environment):
    return True


def deinit(module_id):
    return True


def inform_super(module_id, qstate, superqstate, qdata):
    return True


def operate(module_id, event, qstate, qdata):
    if event in (MODULE_EVENT_NEW, MODULE_EVENT_PASS):
        qstate.ext_state[module_id] = MODULE_WAIT_MODULE
    elif event == MODULE_EVENT_MODDONE:
        qstate.ext_state[module_id] = MODULE_FINISHED
    else:
        qstate.ext_state[module_id] = MODULE_ERROR
    return True
