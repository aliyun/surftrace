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
srcPath = "/root/2ext/vmhive/aarch64/pack"
dstPath = "/root/2ext/nhive/"


if __name__ == "__main__":
    g = CgroupWork(srcPath, maxL=14)
    g.work(workPath, dstPath)
    pass
