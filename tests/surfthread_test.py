# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfthread_test.py
   Description :
   Author :       liaozhaoyan
   date：          2022/3/21
-------------------------------------------------
   Change Activity:
                   2022/3/21:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
import sys
sys.path.append("../")
from surftrace.surfThread import CsurfThread
from surftrace.execCmd import CexecCmd

lines = ""


def cbShow(line):
    global lines
    lines += line
    print(line)


def surftraceSetup(cmds):
    global lines
    lines = ""
    c = CexecCmd()
    s = CsurfThread(cmds, cb=cbShow)
    cmd = "echo > /sys/kernel/debug/tracing/instances/surftrace/trace"
    c.system(cmd)
    s.start()
    time.sleep(1)
    s.stop()
    if "Traceback (most recent call last)" in lines:
        raise Exception("test failed.")


def test_kprobe():
    surftraceSetup(['p wake_up_new_task', 'r wake_up_new_task'])


def test_kprobe_part():
    surftraceSetup(['p copy_process'])


def test_kprobeArgs():
    surftraceSetup(['p do_filp_open dfd=%0', 'p do_filp_open dfd=X%0'])


def test_kprobeArgMeber():
    surftraceSetup(['p wake_up_new_task comm=%0->comm',
                    'p wake_up_new_task uesrs=S%0->mm->mm_users',
                    'p wake_up_new_task node=%0->se.run_node.rb_left'])


def test_kprobeSkb():
    surftraceSetup(['p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=X@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1',
                    'p ip_local_deliver len=@(struct iphdr*)%0->ihl',
                    'p tcp_rcv_established aseq=@(struct tcphdr*)l4%0->ack_seq'
                    ])

def test_globalVars():
    surftraceSetup([
        'p brnf_sysctl_call_tables comm=$comm value=%2 value2=@jiffies',
        'p brnf_sysctl_call_tables comm=$comm value=%2 value2=@(struct tcphdr*)l4@jiffies->ack_seq',
    ]
    )


def test_Events():
    expr = [
            'e syscalls/sys_enter_dup',
            'e syscalls/sys_enter_creat',
            'e syscalls/sys_enter_close',
            'e syscalls/sys_enter_chmod',
            'e sched/sched_stat_wait f:delay>1000',
            ]
    surftraceSetup(expr)


if __name__ == "__main__":
    pass
