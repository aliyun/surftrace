# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     javaProbe
   Description :
   Author :       liaozhaoyan
   date：          2022/10/18
-------------------------------------------------
   Change Activity:
                   2022/10/18:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from signal import pause
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

SEC("perf_event")
int bpf_prog(struct bpf_perf_event_data *ctx)
{
    bpf_printk("java function probe. arg1 :%d\n", ctx->regs.si);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CjavaProbe(ClbcBase):
    def __init__(self, pid, sym):
        super(CjavaProbe, self).__init__("perfBp", bpf_str=bpfPog)
        self.attachJavaSym("bpf_prog", pid, sym)

    def loop(self):
        pause()


if __name__ == "__main__":
    j = CjavaProbe(int(sys.argv[1]), sys.argv[2])
    j.loop()
    pass
