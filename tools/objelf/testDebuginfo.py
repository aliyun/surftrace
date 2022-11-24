# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     testDebuginfo
   Description :
   Author :       liaozhaoyan
   date：          2022/11/7
-------------------------------------------------
   Change Activity:
                   2022/11/7:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
from objelf import CobjElf


class CtestDebug(object):
    def __init__(self, dPath, db):
        super(CtestDebug, self).__init__()
        self._dPath = dPath
        self._db = db

    def walkVmLinux(self):
        g = os.walk(self._dPath)
        for path, dirL, fileL in g:
            for fName in fileL:
                if fName.startswith("vmlinux"):
                    vmPath = os.path.join(path, fName)
                    try:
                        obj = CobjElf(vmPath)
                        obj.toDb("vmlinux", self._db)
                    except Exception as e:
                        print("vmlinux parse failed, report %s, pid %d" % (repr(e), os.getpid()))
                    break

    def _parseKo(self, path, ko):
        if ko.endswith("ko"):
            mod = ko.rsplit(".", 1)[0]
        else:
            mod = ko.rsplit(".", 2)[0]
        vmPath = os.path.join(path, ko)
        try:
            obj = CobjElf(vmPath)
            obj.toDb(mod, self._db)
        except Exception as e:
            print("ko %s parse failed, report %s, pid %d" % (ko, repr(e), os.getpid()))

    def walkKo(self):
        g = os.walk(self._dPath)
        for path, dirL, fileL in g:
            for fName in fileL:
                if fName.endswith("ko") or fName.endswith("ko.debug"):
                    self._parseKo(path, fName)

    def work(self):
        self.walkVmLinux()
        self.walkKo()


if __name__ == "__main__":
    t = CtestDebug("/root/1ext/release", "test.db")
    t.work()
    pass
