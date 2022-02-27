# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfCommon_test.py
   Description :
   Author :       liaozhaoyan
   date：          2022/2/27
-------------------------------------------------
   Change Activity:
                   2022/2/27:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
sys.path.append("../")
from surftrace.surfCommon import transProbeLine


def test_transProbeLine_probe():
    probeString = 'jbd2/vda1-8-313   [000] .... 234372.103866: f0: (blk_account_io_start+0x0/0x180) request=18446617219543870720 disk="vda" comm="jbd2/vda1-8"'
    res = transProbeLine(probeString)
    args = res['args']
    assert args['disk'] == "vda"


def test_transProbeLine_event():
    eventString = 'kworker/u4:0-103806  [000] d... 445702.516774: sched_stat_wait: comm=bash pid=103869 delay=1843 [ns]'
    res = transProbeLine(eventString)
    pid = res['pid']
    assert pid == 103806


def test_transProbeLine_event2():
    eventString = 'kworker/1:1H-115     [001] .... 651700.858481: block_rq_issue: 253,0 FF 0 () 0 + 0 [kworker/1:1sH]'
    res = transProbeLine(eventString)
    args = res['args']
    assert args == "253,0 FF 0 () 0 + 0 [kworker/1:1sH]"


def test_transProbeLine_syscall():
    syscallString = 'sem-104831  [001] .... 448036.804764: sys_futex(uaddr: 7f1a90bc9910, op: 0, val: 19989, utime: 0, uaddr2: 0, val3: 7f1a903c8640)'
    res = transProbeLine(syscallString)
    args = res['args']
    assert args['uaddr'] == '7f1a90bc9910'


def test_transProbeLine_syscallret():
    syscallString = 'sem-104831  [001] .... 448036.804808: sys_futex -> 0x0'
    res = transProbeLine(syscallString)
    ret = res['return']
    assert ret == 0

if __name__ == "__main__":
    pass
