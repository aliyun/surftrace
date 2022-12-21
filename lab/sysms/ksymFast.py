# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ksymFast.py
   Description :
   Author :       liaozhaoyan
   date：          2022/12/20
-------------------------------------------------
   Change Activity:
                   2022/12/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
import mmap
import struct
import tempfile
import functools


class CksymFast(object):
    def __init__(self):
        super(CksymFast, self).__init__()
        self._formatS = "Q64s31sc"  # 8 + 64 + 31 + 1
        self._cellSize = 104
        self._f = tempfile.TemporaryFile()
        self._nums = self._load()
        self._size()
        self._mm = mmap.mmap(self._f.fileno(), self._nums * self._cellSize)

    def _size(self):
        self._f.seek(0, os.SEEK_END)
        return self._f.tell()

    def _sort(self, strA, strB):
        sA, _ = strA.split(" ", 1)
        sB, _ = strB.split(" ", 1)

        addrA = int("0x" + sA, 16)
        addrB = int("0x" + sB, 16)
        return addrA - addrB

    def _load(self, fName="/proc/kallsyms"):
        lines = []
        with open(fName, "r") as f:
            for line in f.readlines():
                line = line.rstrip("\n")
                lines.append(line)
        lines.sort(key=functools.cmp_to_key(self._sort))

        nums = 0
        for line in lines:
            addr, t, syms = line.split(' ')
            addr = int("0x" + addr, 16)
            if '\t' in syms:
                syms, mod = syms.split("\t")
            else:
                mod = ""
            stream = struct.pack(self._formatS, addr, syms.encode(), mod.encode(), t.encode())
            self._f.write(stream)
            nums += 1
        return nums

    def _value(self, i):
        off = i * self._cellSize
        stream = self._mm[off: off + 8]
        v = struct.unpack("Q", stream)
        return v[0]

    def _sym(self, i):
        off = i * self._cellSize + 8
        stream = self._mm[off: off + 64]
        v = struct.unpack("64s", stream)
        return v[0].decode().rstrip("\x00")

    def _cell(self, i):
        off = i * self._cellSize
        stream = self._mm[off: off + self._cellSize]
        addr, syms, mod, t = struct.unpack(self._formatS, stream)
        return {"addr": addr,
                "syms": syms.decode().rstrip("\x00"),
                "mod": mod.decode().rstrip("\x00"),
                "t": t,
                }

    def addr2sym(self, addr):
        start = 0
        end = self._nums - 1

        while start < end:
            mid = start + (end - start) // 2
            midv = self._value(mid)
            if addr < midv:
                end = mid
            elif addr > midv:
                start = mid + 1
            else:
                return self._cell(mid)

        if start > 0 and self._value(start - 1) < addr:
            return self._cell(start - 1)

        elif start == end:
            return self._cell(end)

        return None

    def sym2addr(self, sym):
        for i in range(self._nums):
            func = self._sym(i)
            if func == sym:
                return self._cell(i)
        return None


if __name__ == "__main__":
    f = CksymFast()
    print(f.addr2sym(0xffffffffc024fac8))
    print(f.sym2addr("print_unex"))
    pass
