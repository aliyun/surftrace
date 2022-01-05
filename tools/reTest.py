# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     reTest.py
   Description :
   Author :       liaozhaoyan
   date：          2022/1/4
-------------------------------------------------
   Change Activity:
                   2022/1/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import re

rem1 = re.compile(r"\/\* *[\d]+( *|: *[\d] *)\| *[\d]+ *\*\/")
s = "/*    0      |   136 */    struct sock_common {"
res = rem1.search(s)
print(res.group())

ver = re.compile(r"[\d]+\.[\d]+")
s = "GNU gdb (GDB) 9.2"
s2 = "GNU gdb (GDB) Red Hat Enterprise Linux 7.6.1-120.1.al7"
res = ver.search(s2)
print(res.group())

if __name__ == "__main__":
    pass
