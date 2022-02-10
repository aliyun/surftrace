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

import os
import math
from collections import deque

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

    def _transUnit2(self, v):
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
        ind = int((len(str(v)) - 1) / 3)
        if ind > 0:
            unit = HIST_UNIT[ind - 1]
            v /= 1000 ** ind
        return "%d%s" % (v, unit)

    def _showHist2(self, lShow):
        start, end = self._getRegion(lShow)
        maxV = len(self)
        maxColumns = os.get_terminal_size().columns
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
        maxColumns = os.get_terminal_size().columns
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
                ind = int(math.log2(v))
                lShow[ind + 1] += 1
            else:
                lShow[0] += 1
        self._showHist2(lShow)

    def hist10(self):
        lShow = [0] * HIST10_MAX
        for v in self:
            if v > 0:
                ind = len(str(v)) - 1
                lShow[ind] += 1
            else:
                lShow[0] += 1
        self._showHist10(lShow)

if __name__ == "__main__":
    pass
