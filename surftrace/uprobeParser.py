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
from .surfException import FileNotExistException, InvalidArgsException


class CuprobeParser(CgdbParser):
    def __init__(self, obj, gdb=None):
        self._libD = {}
        obj = self._setupObj(obj)
        self._obj = obj
        super(CuprobeParser, self).__init__(obj, gdb)
        self._reBraces = re.compile(r"(?<=\{).+?(?=\})")
        self._beg = self._setupBeg()

    def _setupBeg(self):
        cmd = "objdump -x %s" % self._obj
        lines = self._cmd.cmd(cmd)
        for line in lines.split('\n'):
            s = line.strip()
            if s.startswith("LOAD off"):
                # LOAD off    0x0000000000000000 vaddr 0x0000000000000000 paddr 0x0000000000000000
                s = re.sub(" +", " ", s)
                vs = s.split(" ")
                v = vs[4]
                return int(v, 16)
        raise ValueError("file has not LOAD off segments.")

    def _setupObj(self, obj):
        if '/' in obj:
            if os.path.exists(obj):
                res = os.path.abspath(obj)
            else:
                raise InvalidArgsException("can not find file %s." % obj)
        else:
            cmd = CexecCmd()
            res = cmd.cmd("which %s" % obj)
            if res == "":
                try:
                    res = self._findLib(obj)
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
        self._write("p %s" % func)
        # $3 = {<text variable, no debug info>} 0x48a870 <readline>
        try:
            res = self._read().split('\n')[-2]
        except IndexError:
            raise InvalidArgsException("can not find function %s in file %s" % (func, self._obj))
        addr = res.split(" ")[-2]
        v = int(addr, 16) - self._beg
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
