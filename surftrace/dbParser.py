# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     dbParser
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os

from .baseDbParser import CbaseDbParser, DbException
from .prevPareser import CprevPareser
from .execCmd import CexecCmd


class CdbParser(CbaseDbParser):
    def __init__(self, dbPath=""):
        if dbPath == "":
            c = CexecCmd()
            ver = c.cmd('uname -r')
            dbPath = "info-%s.db" % ver
        if not os.path.exists(dbPath):
            raise DbException("db %s is not exist." % dbPath)
        super(CdbParser, self).__init__(dbPath)
        self._prev = CprevPareser()

    def getFunc(self, func, ret=None, arg=None):
        if self._prev.exist:
            res = self._prev.getFunc(func, ret, arg)
            if self._checkRes(res):
                return res
        return super(CdbParser, self).getFunc(func, ret, arg)

    def getStruct(self, sStruct):
        if self._prev.exist:
            res = self._prev.getFunc(sStruct)
            if self._checkRes(res):
                return res
        return super(CdbParser, self).getStruct(sStruct)

    def getType(self, t):
        if self._prev.exist:
            res = self._prev.getType(t)
            if self._checkRes(res):
                return res
        return super(CdbParser, self).getType(t)


if __name__ == "__main__":
    pass
