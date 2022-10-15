# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     testUprobe
   Description :
   Author :       liaozhaoyan
   date：          2022/10/16
-------------------------------------------------
   Change Activity:
                   2022/10/16:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from signal import pause
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

SEC("uprobe/*")
int call_symbol(struct pt_regs *ctx)
{
    bpf_printk("catch uprobe.\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CtestUprobe(ClbcBase):
    def __init__(self):
        super(CtestUprobe, self).__init__("tUprobe", bpf_str=bpfPog, attach=0)

        self.attachUprobe("call_symbol", -1, "/usr/bin/bash", 0x8a870)
        pause()


if __name__ == "__main__":
    CtestUprobe()
    pass

