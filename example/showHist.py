# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     showHist
   Description :
   Author :       liaozhaoyan
   date：          2022/2/10
-------------------------------------------------
   Change Activity:
                   2022/2/10:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from surftrace.surfCommon import CsurfList
import random

if __name__ == "__main__":
    l = CsurfList(2048)
    for i in range(2048):
        l.append(random.randint(0, 1024 * 1024))
    print("hist2:")
    l.hist2()
    print("hist10:")
    l.hist10()
    pass
