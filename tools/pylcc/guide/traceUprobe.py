# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     traceUprobe
   Description :
   Author :       liaozhaoyan
   date：          2022/10/18
-------------------------------------------------
   Change Activity:
                   2022/10/18:
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


class CtraceUprobe(ClbcBase):
    def __init__(self):
        super(CtraceUprobe, self).__init__("traceUprobe", bpf_str=bpfPog, attach=0)

        self.traceUprobes("call_symbol", -1, "bash:readline")
        pause()


if __name__ == "__main__":
    CtraceUprobe()
    pass

