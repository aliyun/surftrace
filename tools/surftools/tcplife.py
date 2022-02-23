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
birth = {}
skpid = {}
skcomm = {}
def callback(line):
    global birth, skpid, skcomm
    args = transProbeLine(line)
    if args['func'] == 'tcp_set_state':
        times = args['time']
        pid = args['pid']
        comm = args['args']['comm']
        sk = args['args']['sk']
        
        newstate = args['args']['newstate']
        if int(newstate) < tcp_states.index('FIN_WAIT1') and sk not in birth:
            birth[sk] = times
        if int(newstate) == tcp_states.index('SYN_SENT') or int(newstate) == tcp_states.index('LAST_ACK'):
            skpid[sk] = pid
            skcomm[sk] = comm
        if int(newstate) == tcp_states.index('CLOSE') and sk in birth :
            delta_ms = (float(times) - float(birth[sk])) * 1000.0
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            pids = skpid[sk]
            comms = skcomm[sk]
            saddr = args['args']['ip_saddr']
            lport = args['args']['lport']
            daddr = args['args']['ip_daddr']
            dport = args['args']['b16_dport']
            bytes_acked = args['args']['bytesacked']
            bytes_received = args['args']['bytesreceived']
            print("%-20s %-10s %-20s %-16s %-8s %-16s %-8s %5d %5d %5d" % 
                    (timestamp, pids, comms, saddr, lport, daddr, dport, int(bytes_acked)/1024, int(bytes_received)/1024, int(delta_ms)))

expr = ['p tcp_set_state \
        sk=%0 \
        family=%0->__sk_common.skc_family \
        ip_daddr=%0->__sk_common.skc_daddr \
        ip_saddr=%0->__sk_common.skc_rcv_saddr \
        lport=%0->__sk_common.skc_num \
        b16_dport=%0->__sk_common.skc_dport    \
        bytesacked=!(struct tcp_sock *)%0->bytes_acked \
        bytesreceived=!(struct tcp_sock *)%0->bytes_received \
        newstate=%1 \
        comm=$comm']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print("Tracing tcp connections. Hit Ctrl-C to end.\n")
    print("%-20s %-10s %-20s %-16s %-8s %-16s %-8s %-6s %-6s %-6s" % ("TIME", "PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT", "TX_KB", "RX_KB", "MS"))
    surf.loop()
