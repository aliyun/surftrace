# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     tSurf
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
from surftrace.surfThread import CsurfThread

t = CsurfThread(['p wake_up_new_task', 'r wake_up_new_task'], log="out.log")
t.start()
time.sleep(1)
t.stop()


if __name__ == "__main__":
    pass
