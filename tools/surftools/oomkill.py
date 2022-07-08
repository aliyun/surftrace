# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     oomkill
   Description :
   Author :       zhongwuqiang
   date：          2022/2/18
-------------------------------------------------
   Change Activity:
                   2022/2/18:
-------------------------------------------------
"""
__author__ = 'zhongwuqiang'

from surftrace import surftrace, setupParser
from surftrace.surfCommon import CsurfList,transProbeLine
import time

def callback(line):
    args = transProbeLine(line)
    if args['func'] == 'oom_kill_process':
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        pid = args['pid']
        comm = args['args']['comm']
        chosen_pid = args['args']['chosenpid']
        chosen_comm = args['args']['chosencomm']
        totalpages = args['args']['totalpages']
        print("%s Triggered by PID %s (\"%s\"), OOM kill of PID %s (\"%s\"), %s pages " %
                (timestamp, pid, comm, chosen_pid, chosen_comm, totalpages))

# stress --vm 70 --vm-bytes 1073741824 --vm-hang 20
expr = ['p oom_kill_process  \
        chosenpid=%0->chosen->pid \
        chosencomm=%0->chosen->comm \
        totalpages=%0->totalpages \
        comm=$comm']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print("Tracing oom_kill_process()... Hit Ctrl-C to end.\n")
    surf.loop()
