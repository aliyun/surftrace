# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     common
   Description :
   Author :       liaozhaoyan
   date：          2022/2/10
-------------------------------------------------
   Change Activity:
                   2022/2/10:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from collections import deque
from surftrace import CexecCmd
import shlex

HIST2_MAX = 65
HIST10_MAX = 20
HIST_UNIT = "KMGPTE"

class CsurfList(deque):
    def __init__(self, maxLen=1024):
        super(CsurfList, self).__init__(maxlen=maxLen)

    def _getRegion(self, lShow):
        start = end = -1
        for i in range(len(lShow)):
            if lShow[i] != 0:
                end = i
                if start == -1:
                    start = i
        if start == -1:
            raise ValueError("The input list is empty or all zero.")
        return start, end

    @staticmethod
    def _log2(v):
        i = 0
        while v:
            v >>= 1
            i += 1
        return i

    @staticmethod
    def _log10(v):
        i = 0
        while v >= 10:
            v /= 10
            i += 1
        return i

    @staticmethod
    def _transUnit2(v):
        if v < 1:
            return "0"
        v -= 1
        unit = ""
        ind = int(v / 10)
        if ind > 0:
            unit = HIST_UNIT[ind - 1]
            v -= ind * 10
        return "%d%s" % (2**v, unit)

    def _transUnit10(self, v):
        if v < 1:
            return "0"
        unit = ""
        ind = int(self._log10(v) / 3)
        if ind > 0:
            unit = HIST_UNIT[ind - 1]
            v /= 1000 ** ind
        return "%d%s" % (v, unit)

    @staticmethod
    def _getColumns():
        c = CexecCmd()
        vs = c.cmd("stty size")
        return int(vs.split(' ')[1])

    def _showHist2(self, lShow):
        start, end = self._getRegion(lShow)
        maxV = len(self)
        maxColumns = self._getColumns()
        if maxColumns < 30:
            raise OverflowError("this terminal is too short to show histogram.")
        """[256K,512K) 1004|@@@@@@@@@@|"""
        bars = maxColumns - 18
        for i in range(start, end + 1):
            nums = int(lShow[i] * bars / maxV)
            fill = '@' * nums
            blank = ' ' * (bars - nums)
            head = "[%s,%s)" % (self._transUnit2(i), self._transUnit2(i + 1))
            print("%-12s%-4s|%s%s|" % (head, self._transUnit10(lShow[i]), fill, blank))

    def _showHist10(self, lShow):
        start, end = self._getRegion(lShow)
        maxV = len(self)
        maxColumns = self._getColumns()
        if maxColumns < 30:
            raise OverflowError("this terminal is too short to show histogram.")
        """[10K,100K)  1004|@@@@@@@@@@|"""
        bars = maxColumns - 18
        for i in range(start, end + 1):
            nums = int(lShow[i] * bars / maxV)
            fill = '@' * nums
            blank = ' ' * (bars - nums)
            if i == 0:
                head = "[0, 10)"
            else:
                head = "[%s,%s)" % (self._transUnit10(10 ** i), self._transUnit10(10 ** (i + 1)))
            print("%-12s%-4s|%s%s|" % (head, self._transUnit10(lShow[i]), fill, blank))

    def hist2(self):
        lShow = [0] * HIST2_MAX
        for v in self:
            if v > 0:
                ind = int(self._log2(v))
                lShow[ind + 1] += 1
            else:
                lShow[0] += 1
        self._showHist2(lShow)

    def hist10(self):
        lShow = [0] * HIST10_MAX
        for v in self:
            if v > 0:
                ind = self._log10(v)
                lShow[ind] += 1
            else:
                lShow[0] += 1
        self._showHist10(lShow)


def transProbeLine(line):
    '''jbd2/vda1-8-313   [000] .... 234372.103866: f0: (blk_account_io_start+0x0/0x180) request=18446617219543870720 disk="vda" comm="jbd2/vda1-8"'''
    tasks, rest = line.split(" [", 1)
    task, pid = tasks.strip().rsplit('-', 1)
    res = {"task": task, "pid": int(pid)}
    cpu, rest = rest.split("] ", 1)
    res["cpu"] = int(cpu)
    flag, rest = rest.split(" ", 1)
    res["flag"] = flag
    ts, name, rest = rest.split(": ")
    res["time"] = ts
    res["name"] = name.strip()
    _, rest = rest.split("(", 1)
    funcs, args = rest.split(")", 1)
    func, sizes = funcs.split("+", 1)
    pos, size = sizes.split("/", 1)
    res['func'] = func
    res['pos'] = int(pos, 16)
    res['size'] = int(size, 16)
    argd = {}
    for a in shlex.split(args.strip()):
        k, v = a.split('=', 1)
        argd[k] = v
    res['args'] = argd
    return res

import random
if __name__ == "__main__":
    print(transProbeLine('jbd2/vda1-8-313   [000] .... 234372.103866: f0: (blk_account_io_start+0x0/0x180) request=18446617219543870720 disk="vda" comm="jbd2/vda1-8"'))
