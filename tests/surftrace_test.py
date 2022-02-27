# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surftrace_test.py
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
from surftrace.surftrace import surftrace, setupParser


def cbShow(line):
    print(line)


def surftraceSetup(cmds):
    parser = setupParser()
    s = surftrace(cmds, parser, show=True, echo=False, cbShow=cbShow)
    s.start()


def test_kprobe():
    surftraceSetup(['p wake_up_new_task', 'r wake_up_new_task'])


def test_kprobeArgs():
    surftraceSetup(['p do_filp_open dfd=%0', 'p do_filp_open dfd=X%0'])


def test_kprobeArgMeber():
    surftraceSetup(['p wake_up_new_task comm=%0->comm',
                    'p wake_up_new_task uesrs=S%0->mm->mm_users',
                    'p wake_up_new_task node=%0->se.run_node.rb_left'])


if __name__ == "__main__":
    pass
