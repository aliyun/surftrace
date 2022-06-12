# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     lbcInc
   Description :
   Author :       liaozhaoyan
   date：          2022/6/10
-------------------------------------------------
   Change Activity:
                   2022/6/10:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import re

INCLUDE_MAX = 64


class ClbcInclude(object):
    def __init__(self, workPath=None, incPath=None):
        super(ClbcInclude, self).__init__()
        self._reInclude = re.compile(r'^#include *[\<\"].*[\>\"]')
        self._reBrackets = re.compile(r'(?<=[\<\"]).+?(?=[\>\"])')
        self._loop = 0

        if workPath is None:
            workPath = os.getcwd()
        self._incs = [workPath]

        if "LBC_INCLUDE" in os.environ:
            incPath = os.environ["LBC_INCLUDE"] + ";" + incPath
        if incPath is not None:
            paths = incPath.split(';')
            for path in paths:
                if os.path.exists(path) and os.path.isdir(path):
                    self._incs.append(os.path.abspath(path))
                else:
                    print("warning: path %s is not exist, skip.", path)

    def _loadFile(self, fileName):
        workDir = os.getcwd()
        strInc = None
        for path in self._incs:
            os.chdir(path)
            if os.path.exists(fileName):
                with open(fileName, 'r') as fInc:
                    strInc = fInc.read()
        os.chdir(workDir)

        self._loop += 1
        if self._loop > INCLUDE_MAX:
            raise ValueError("include %s may nested include.", fileName)
        if strInc is None:
            raise ValueError("include %s is not exist.", fileName)
        return self._parse(strInc)

    def _parse(self, s):
        res = []
        lines = s.split('\n')
        for line in lines:
            r = self._reInclude.search(line)
            if r:
                fileName = self._reBrackets.search(line).group().strip()
                if fileName == "lbc.h":
                    res.append(line)
                else:
                    res += self._loadFile(fileName)
            else:
                res.append(line)
        return res

    def parse(self, bpfStr):
        res = []
        res += self._parse(bpfStr)
        return "\n".join(res)


if __name__ == "__main__":
    inc = ClbcInclude(incPath="/Users/liaozhaoyan/work/sh/c")
    with open("test.bpf.c", 'r') as f:
        s = f.read()
    inc.parse(s)
    pass
