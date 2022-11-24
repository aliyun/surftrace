# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     multiX64
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

workPath = "/dump/4/vmhive/work"
srcPath = "/dump/4/vmhive/x86_64/pack"
dstPath = "/dump/4/vmhive/"

if __name__ == "__main__":
    g = CgroupWork(srcPath, maxL=24)
    g.work(workPath, dstPath)
    pass
