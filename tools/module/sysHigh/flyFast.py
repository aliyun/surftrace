# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     flyFast
   Description :
   Author :       liaozhaoyan
   date：          2022/12/13
-------------------------------------------------
   Change Activity:
                   2022/12/13:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import time
import random
from multiprocessing import Process

PROC_FILE = "/proc/coolbpf/sys_fly"


class CworkThread(Process):
    def __init__(self):
        super(CworkThread, self).__init__()
        self.start()

    def run(self):
        while True:
            fd = os.open(PROC_FILE, os.O_RDWR)
            p, v = os.read(fd, 64).decode().split(':')
            v = int(v) + 1
            os.write(fd, "%d".encode() % v)
            os.close(fd)

            time.sleep(1)


class CnoiseThread(Process):
    def __init__(self):
        super(CnoiseThread, self).__init__()
        self.start()

    def run(self):
        while True:
            time.sleep(random.randint(15, 30))
            fd = os.open(PROC_FILE, os.O_RDWR)
            p, v = os.read(fd, 64).decode().split(':')
            v = int(v) + 10
            os.write(fd, "%d".encode() % v)
            os.close(fd)


if __name__ == "__main__":
    w = CworkThread()
    n = CnoiseThread()
    w.join()
    n.join()
    pass
