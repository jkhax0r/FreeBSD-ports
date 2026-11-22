"""Explicit native optional RAM-counter controls; never starts/stops DNS itself."""
import argparse
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from .counterstore import CounterStore,ROOT,DATA
from .countercron import CounterCron
from .lifecycle import current

def operate(action):
    store=CounterStore();cron=CounterCron(store)
    if action=='inspect':return {'storage':store.inspect(),'schedule':cron.inspect()}
    if action=='enable':
        observed=store.inspect()
        if observed.get('mode')=='ram':
            return {'storage':{'active':True,'unchanged':True},'schedule':cron.install(),'resolver_started':False}
        # Detect an existing foreign cron entry before moving counter data.
        store.provision();cron.inspect()
        return {'storage':store.activate(),'schedule':cron.install(),'resolver_started':False}
    if action=='abort':
        if cron.inspect()['installed']:raise ValueError('Inspect the installed checkpoint schedule before cancelling setup')
        return store.abort()
    if action=='disable':
        if not os.path.lexists(store.control):return {'storage':{'configured':False,'disabled':True},'schedule':cron.inspect(),'unchanged':True}
        if store._read()['checkpoint']['phase']=='off':
            store.removable()
            return {'storage':{'disabled':True,'unchanged':True},'schedule':cron.remove(),'resolver_started':False}
        store._authority(True);store._quiescent()
        return {'schedule':cron.remove(),'storage':store.disable(),'resolver_started':False}
    if action=='checkpoint':
        if not os.path.lexists(store.control)or store._read()['checkpoint']['phase']=='off':return {'checkpointed':False,'mode':'original_disk'}
        return store.checkpoint()
    raise ValueError('Explicit counter RAM operation required')

def main(argv=None):
    parser=argparse.ArgumentParser(description='Optional RAM-backed provider counters, with recent-change loss after crash. Enable/disable require a stopped resolver. No DNS hooks, aliases or rules are changed.')
    parser.add_argument('action',choices=('inspect','enable','disable','checkpoint','abort'));args=parser.parse_args(argv)
    try:print(json.dumps(operate(args.action)));return 0
    except(OSError,ValueError,RuntimeError,sqlite3.Error,subprocess.SubprocessError)as error:
        print('Counter RAM operation not confirmed: '+str(error)[:400]+'. Inspect storage/schedule state before retrying.',file=sys.stderr);return 1

def cli():
    if any(arg in('-h','--help')for arg in sys.argv[1:]):return main()
    if not sys.platform.startswith('freebsd')or Path(__file__).resolve()!=ROOT/'dnsalias/counterram.py':
        print('Counter RAM requires the installed native package',file=sys.stderr);return 1
    if current(ROOT,DATA)is None:
        os.execve(sys.executable,[sys.executable,'-B',str(ROOT/'dnsalias/lifecycle.py'),'operator','counterram',*sys.argv[1:]],os.environ.copy())
    return main()

if __name__=='__main__':raise SystemExit(cli())
