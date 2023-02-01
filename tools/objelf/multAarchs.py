# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     multAarchs
   Description :
   Author :       liaozhaoyan
   date：          2022/11/14
-------------------------------------------------
   Change Activity:
                   2022/11/14:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from mulitWork import CgroupWork

workPath = "/root/1ext/work"
srcPath = "/root/1ext/pack"
dstPath = "/root/1ext"


if __name__ == "__main__":
    g = CgroupWork(srcPath, maxL=32)
    g.work(workPath, dstPath)
    pass
