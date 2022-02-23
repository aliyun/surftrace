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

tcp_states = ["unkown","ESTABLISHED","SYN_SENT","SYN_RECV","FIN_WAIT1","FIN_WAIT2","TIME_WAIT","CLOSE","CLOSE_WAIT","LAST_ACK","LISTEN","CLOSING","NEW_SYN_RECV"]
def callback(line):
    args = transProbeLine(line)
    if args['func'] == 'tcp_retransmit_skb':
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        pid = args['pid']
        comm = args['args']['comm']
        saddr = args['args']['ip_saddr']
        lport = args['args']['lport']
        daddr = args['args']['ip_daddr']
        dport = args['args']['b16_dport']
        state = args['args']['state']
        print("%-20s %-10s %-20s %20s:%-6s %20s:%-6s %10s" % 
                (timestamp, pid, comm, saddr, lport, daddr, dport, tcp_states[int(state)]))

expr = ['p tcp_retransmit_skb \
        family=%0->__sk_common.skc_family \
        ip_daddr=%0->__sk_common.skc_daddr \
        ip_saddr=%0->__sk_common.skc_rcv_saddr \
        lport=%0->__sk_common.skc_num \
        b16_dport=%0->__sk_common.skc_dport    \
        state=%0->__sk_common.skc_state \
        comm=$comm']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print("Tracing tcp connections. Hit Ctrl-C to end.\n")
    print("%-20s %-10s %-20s %26s %27s %11s" % ("TIME", "PID", "COMM", "SADDR:SPORT", "DADDR:DPORT", "STATE"))
    surf.loop()
