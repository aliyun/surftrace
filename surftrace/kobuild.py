# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     kobuild.py
   Description :
   Author :       liaozhaoyan
   date：          2022/5/27
-------------------------------------------------
   Change Activity:
                   2022/5/27:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
from .lbcClient import ClbcClient, segEncode, segDecode

MAX_FILES = 32
MAX_LENS = 16 * 1024 * 1024


class CkoBuilder(object):
    def __init__(self):
        self._cli = ClbcClient()
        super(CkoBuilder, self).__init__()

    def _getko(self, path, name):
        with open(os.path.join(path, name), 'rb') as f:
            stream = f.read()
        return stream

    def _checkSize(self, outLen, cnt):
        if outLen > MAX_LENS:
            raise ValueError("file sizes is over than %d" % MAX_LENS)
        if cnt > MAX_FILES:
            raise ValueError("file counts is over than %d" % MAX_FILES)

    def build(self, iPath, out="prev.db"):
        if not os.path.isdir(iPath):
            raise ValueError("%s is not a dir." % iPath)

        outD = {}
        outLen = 0
        cnt = 0
        g = os.walk(iPath)
        for path, dirL, fileL in g:
            for fName in fileL:
                if fName.endswith("ko") or fName.endswith("ko.debug"):
                    stream = self._getko(path, fName)
                    outLen += len(stream)
                    cnt += 1
                    self._checkSize(outLen, cnt)
                    if fName in outD:
                        raise ValueError("file: %s is duplicated." % fName)
                    outD[fName] = segEncode(stream).decode()
        dRecv = self._cli.koBuild(outD)
        if 'db' not in dRecv:
            print(dRecv.keys())
            raise ValueError("remote sever return error.")
        with open(out, "wb") as f:
            f.write(segDecode(dRecv['db']))


def main():
    k = CkoBuilder()
    k.build(sys.argv[1])


if __name__ == "__main__":
    main()
    pass
