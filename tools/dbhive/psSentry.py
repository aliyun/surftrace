# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     psSentry
   Description :
   Author :       liaozhaoyan
   date：          2022/1/24
-------------------------------------------------
   Change Activity:
                   2022/1/24:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import psutil
import time

class CpsSentry(object):
    def __init__(self):
        super(CpsSentry, self).__init__()
        self._gdbd = {}

    def proc(self):
        pids = psutil.pids()
        idL = []
        for p in pids:
            try:
                task = psutil.Process(p)
            except psutil.NoSuchProcess:
                continue
            comm = " ".join(task.cmdline())
            if comm.startswith("gdb") and (comm.endswith("ko") or comm.endswith("ko.debug")):
                idL.append(task.pid)
                if task.pid in self._gdbd.keys():
                    self._gdbd[task.pid] += 1
                    if self._gdbd[task.pid] > 8:
                        print(f"need too kill {task.pid}, {comm}, {self._gdbd[task.pid]}")
                        try:
                            task.kill()
                        except (psutil.NoSuchProcess, FileNotFoundError):
                            continue
                else:
                    self._gdbd[task.pid] = 1
        gL = list(self._gdbd.keys())
        for k in gL:
            if k not in idL:
                del self._gdbd[k]

if __name__ == "__main__":
    ps = CpsSentry()
    while True:
        ps.proc()
        time.sleep(60)
    pass
