# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     lbcUstack
   Description :
   Author :       liaozhaoyan
   date：          2022/10/23
-------------------------------------------------
   Change Activity:
                   2022/10/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
from surftrace.surfElf import CelfSym


class ClbcUstack(object):
    def __init__(self, pid, addrs):
        super(ClbcUstack, self).__init__()
        self._pid = pid
        self._addrs = addrs
        self._mmap = self._loadMmaps()
        self._elfs = {}

    def _loadMmaps(self):
        pathName = "/proc/%d/maps" % self._pid

        with open(pathName, 'r') as f:
            lines = f.readlines()

        maps = []
        for line in lines:
            line = re.sub(r" +", " ", line.strip())
            cells = line.split(' ')
            if 'x' in cells[1]:
                start, end = cells[0].split('-')
                d = {"start": int(start, 16), "end": int(end, 16)}
                if len(cells) == 5:
                    d["path"] = None
                else:
                    d["path"] = cells[5]
                maps.append(d)
        return maps

    def _queryElf(self, addr):
        for mmap in self._mmap:
            if mmap['start'] <= addr < mmap['end']:
                return mmap["path"], mmap['start']

        raise OSError("addr 0x%x is an illegal value" % addr)

    def dumpStacks(self):
        lines = []
        for addr in self._addrs:
            if addr == 0:
                break
            try:
                fPath, start = self._queryElf(addr)
            except OSError:
                break
            addr -= start
            if fPath not in self._elfs:
                self._elfs[fPath] = CelfSym(fPath)

            sym, offset = self._elfs[fPath].addr2sym(addr)
            lines.append("%s + 0x%x" % (sym, offset))
        return lines


def getKStacks(maps, stack_id, elfSym, sLen=-1):
    arr = []
    stks = maps.getArr(stack_id)
    if stks is not None:
        if sLen == -1:
            sLen = len(stks)
        for i in range(sLen):
            if stks[i] != 0:
                name, _ = elfSym.ksymSearch(stks[i])
                arr.append(name)
            else:
                break
    return arr


if __name__ == "__main__":
    pass
