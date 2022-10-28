# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     uprobeParser
   Description :
   Author :       liaozhaoyan
   date：          2022/9/23
-------------------------------------------------
   Change Activity:
                   2022/9/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
import os
from .execCmd import CexecCmd
from .gdbParser import CgdbParser
from .surfElf import CelfSym
from .surfException import InvalidArgsException


class CuprobeParser(CgdbParser):
    def __init__(self, obj, gdb=None):
        self._libD = {}
        obj = self._setupObj(obj)
        self._sym = CelfSym(obj)
        self._obj = obj
        super(CuprobeParser, self).__init__(obj, gdb)
        self._reBraces = re.compile(r"(?<=\{).+?(?=\})")
        self._beg = self._setupBeg()

    def _setupBeg(self):
        return self._sym.symOffset()

    def _setupObj(self, obj):
        if obj.startswith('/'):  # abs path
            if os.path.exists(obj):
                res = os.path.abspath(obj)
            else:
                raise InvalidArgsException("can not find file %s." % obj)
        else:   # relative
            res = os.path.join(os.getcwd(), obj)  # pwd
            if os.path.isfile(res):
                pass
            else:
                cmd = CexecCmd()
                res = cmd.cmd("which %s" % obj)   # find cmd in path
                if res == "":
                    try:
                        res = self._findLib(obj)   # find so from libs.
                        print(res)
                    except KeyError:
                        raise InvalidArgsException("can not find lib %s" % obj)
        return res

    def _loadLib(self):
        if len(self._libD) == 0:
            cmd = CexecCmd()
            lines = cmd.cmd("ldconfig -v")
            path = ""
            for line in lines.split('\n'):
                if line.startswith("/"):
                    path = line.split(":", 1)[0]
                else:
                    lib, so = line.split('->', 1)
                    lib = lib.strip()
                    if ".so" in lib:
                        lib = lib.split(".so", 1)[0]
                    self._libD[lib] = os.path.join(path, so.strip())

    def _findLib(self, obj):
        self._loadLib()
        return self._libD[obj]

    def fullObj(self):
        return self._obj

    def funAddr(self, func):
        addr = self._sym.symAddr(func)
        v = addr - self._beg
        return "0x%x" % v

    def getFunc(self, func, ret=None, arg=None):
        self._setupRes()
        if len(func) < 2:
            return {"log": "func len should bigger than 2.", "res": None}

        File = ""
        lineNo = '0'
        self._res['res'] = []
        self._write("p %s" % func)
        try:
            res = self._read().split('\n')[-2]
        except IndexError:
            raise InvalidArgsException("can not find function %s in file %s" % (func, self._obj))

        sFinds = self._reBraces.findall(res)
        if len(sFinds):
            sFind = sFinds[0]
            if sFind == "<text variable, no debug info>":  # no debug symbol.
                ret, args = "int", "int, int, int, int"
            else:
                ret, args = sFind.split('(', 1)  # int (void)
                ret = ret.strip()
                args = args[:-1]
            funcd = {'func': func,
                     'args': self._argFuncSplit(args),
                     'ret': ret,
                     'line': int(lineNo),
                     'file': File}
            self._res['res'].append(funcd)
        return self._res


if __name__ == "__main__":
    pass
