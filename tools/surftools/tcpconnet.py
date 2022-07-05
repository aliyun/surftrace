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
    if args['func'] == 'tcp_connect':
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        pid = args['pid']
        comm = args['args']['comm']
        saddr = args['args']['ip_saddr']
        lport = args['args']['lport']
        daddr = args['args']['ip_daddr']
        dport = args['args']['b16_dport']
        print("%-20s %-10s %-20s %-16s %-8s %-16s %-8s" %
                (timestamp, pid, comm, saddr, lport, daddr,dport))

expr = ['p tcp_connect \
        family=%0->__sk_common.skc_family \
        ip_daddr=%0->__sk_common.skc_daddr \
        ip_saddr=%0->__sk_common.skc_rcv_saddr \
        lport=%0->__sk_common.skc_num \
        b16_dport=%0->__sk_common.skc_dport \
        comm=$comm']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print("Tracing tcp connections. Hit Ctrl-C to end.\n")
    print("%-20s %-10s %-20s %-16s %-8s %-16s %-8s" % ("TIME", "PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT"))
    surf.loop()
