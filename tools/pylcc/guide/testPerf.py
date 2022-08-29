# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     perfEvent
   Description :
   Author :       liaozhaoyan
   date：          2022/8/29
-------------------------------------------------
   Change Activity:
                   2022/8/29:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
from pylcc.lbcBase import ClbcBase
from pylcc.perfEvent import *

bpfPog = r"""
#include "lbc.h"

SEC("perf_event")
int bpf_prog(struct bpf_perf_event_data *ctx)
{
    bpf_printk("hello perf\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CtestPerf(ClbcBase):
    def __init__(self):
        super(CtestPerf, self).__init__("tPerf", bpf_str=bpfPog)

    def loop(self):
        pfConfig = {
            "sample_freq": 50,
            "freq": 1,
            "type": PerfType.SOFTWARE,
            "config": PerfSwIds.PAGE_FAULTS_MIN,
        }
        print(self.attachPerfEvent("bpf_prog", pfConfig))
        while True:
            time.sleep(1)


if __name__ == "__main__":
    perf = CtestPerf()
    perf.loop()
    pass

