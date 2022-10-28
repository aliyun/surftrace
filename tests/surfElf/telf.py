# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     telf
   Description :
   Author :       liaozhaoyan
   date：          2022/10/26
-------------------------------------------------
   Change Activity:
                   2022/10/26:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from surftrace.surfElf import CelfKsym, CelfSym

e = CelfKsym()
res = e.ksymAddr("_do_fork")
print(res)
print(e.ksymSearch(res + 0x00))
print(e.ksymSearch(res + 0x80))
print(e.ksymSearch(res + 0x500))

b = CelfSym("/usr/bin/bash")
res = b.symAddr("readline")
print(res)
print(b.symSearch(res + 0x00))
print(b.symSearch(res + 0x100))
print(b.symSearch(res + 0x200))
print(b.symSearch(res + 0x500))

if __name__ == "__main__":
    pass
