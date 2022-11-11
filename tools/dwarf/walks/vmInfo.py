# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     vmInfo
   Description :
   Author :       liaozhaoyan
   date：          2022/11/5
-------------------------------------------------
   Change Activity:
                   2022/11/5:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from surfDwarf import CdwarfDb

if __name__ == "__main__":
    db = CdwarfDb("/root/1ext/vmhive/x86_64/vmlinux/anolis/vmlinux-5.10.134-12.an8.x86_64",
                  "vmlinux.db")
    db.walks()
    pass
