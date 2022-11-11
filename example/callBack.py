# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     callBack
   Description :
   Author :       liaozhaoyan
   date：          2022/1/5
-------------------------------------------------
   Change Activity:
                   2022/1/5:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
sys.path.append("..")
from surftrace import surftrace, setupParser


def callbackOrig(line):
    print("orig:" + line)


def callback(line):
    print("cb:" + line)


expr = "p _do_fork comm=%0->comm node=%0->pids[1].node.next"
if __name__ == "__main__":
    parser = setupParser("remote")
    # surf = surftrace([expr], parser, cbOrig=callbackOrig)
    surf = surftrace([expr], parser, cb=callback)
    surf.start()
    surf.loop()
    pass
