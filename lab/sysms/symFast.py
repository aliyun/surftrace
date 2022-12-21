# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     symFast
   Description :
   Author :       liaozhaoyan
   date：          2022/12/7
-------------------------------------------------
   Change Activity:
                   2022/12/7:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import struct
import functools
import tempfile


class KsymPos:
    addr = 0
    t = 1
    func = 2
    mod = 3


class CksysmFast(object):
    def __init__(self, fName="/proc/kallsyms"):
        super(CksysmFast, self).__init__()
        self._formatS = "Qc64s32s"
        self._size = 105
        self._f = tempfile.TemporaryFile()
        self._nums = self._load(fName)

    def _sort(self, strA, strB):
        sA, _ = strA.split(" ", 1)
        sB, _ = strB.split(" ", 1)

        addrA = int("0x" + sA, 16)
        addrB = int("0x" + sB, 16)

        return addrA - addrB

    def _load(self, fName):
        lines = []
        with open(fName, "r") as f:
            for line in f.readlines():
                lines.append(line)

        lines.sort(key=functools.cmp_to_key(self._sort))
        for line in lines:
            line = line.rstrip('\n')
            addr, t, syms = line.split(' ')
            addr = int("0x" + addr, 16)
            if '\t' in syms:
                syms, mod = syms.split("\t")
            else:
                mod = ""
            stream = struct.pack(self._formatS, addr, t.encode(), syms.encode(), mod.encode())
            self._f.write(stream)

        return len(lines)

    def _formatCell(self, cell):
        return {"addr": cell[KsymPos.addr],
                "t": cell[KsymPos.t],
                "func": cell[KsymPos.func].decode().rstrip("\x00"),
                "mod": cell[KsymPos.mod].decode().rstrip("\x00")}

    def _qFile(self, num):
        offset = num * self._size
        self._f.seek(offset)
        stream = self._f.read(self._size)
        return struct.unpack(self._formatS, stream)

    def _cellShow(self, cell):
        cell = self._formatCell(cell)
        print("cell: %s, addr:0x%x, type: %s, module: %s" %
              (cell["func"], cell["addr"], cell["t"], cell["mod"]))

    def query(self, addr):
        start = 0
        end = self._nums

        while start < end:
            mid = start + (end - start) // 2
            cell = self._qFile(mid)
            if addr < cell[KsymPos.addr]:
                end = mid
            elif addr > cell[KsymPos.addr]:
                start = mid + 1
            else:
                return self._formatCell(cell)

        if start > 0:
            cell = self._qFile(start)
            cellBack = self._qFile(start - 1)
            print(addr, start)
            self._cellShow(cellBack)
            self._cellShow(cell)
            if cellBack[KsymPos.addr] < addr < cell[KsymPos.addr]:
                return self._formatCell(cellBack)

        elif end == self._nums:
            return self._qFile(end - 1)

        return None

    def symbol(self, func):
        self._f.seek(0)
        for i in range(self._nums):
            stream = self._f.read(self._size)
            cell = struct.unpack(self._formatS, stream)
            if cell[KsymPos.func].decode().rstrip("\x00") == func:
                return self._formatCell(cell)
        return None


if __name__ == "__main__":
    f = CksysmFast()
    print(f.query(0xffffffff820133a1))
    print(f.symbol("__param_str_floppy"))
    pass
