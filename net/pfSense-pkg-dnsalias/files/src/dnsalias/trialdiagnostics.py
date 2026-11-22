"""Bounded failure evidence without commands, paths, raw replies or credentials."""


def summary(owner):
    owner=owner if type(owner) is dict else {}
    operation=owner.get('operation')
    operation=operation if type(operation) is dict else {}
    feed=operation.get('feed_result',operation)
    feed=feed if type(feed) is dict else {}
    rollback=feed.get('rollback') or {}
    cleanup=(feed.get('feed') or {}).get('cleanup') or {}
    def label(value):
        if type(value) is not str:return None
        return value[:160] if all(c.isascii() and (c.isalnum() or c in ' _.:;-') for c in value) else 'Details withheld'
    def flag(value):return value if type(value) is bool else None
    errno=feed.get('error_errno')
    return {'owner_error':label(owner.get('error')),'operation_state':label(operation.get('state')),
        'operation_error':label(operation.get('error')),'feed_state':label(feed.get('state')),
        'feed_error':label(feed.get('error')),'feed_error_errno':errno if type(errno) is int and 0<errno<65536 else None,
        'observation_started':flag(feed.get('observation_started')),
        'observation_failure':label(feed.get('observation_failure')),
        'feed_resources_released':flag(feed.get('resources_released')),
        'feed_cleanup_error':label(cleanup.get('error')),'rollback_phase':label(rollback.get('journal_phase')),
        'worker_exited':flag(rollback.get('worker_exited'))}
