# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     perfBreakpoint
   Description :
   Author :       liaozhaoyan
   date：          2022/10/8
-------------------------------------------------
   Change Activity:
                   2022/10/8:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
from signal import pause
import time
from pylcc.lbcBase import ClbcBase
from pylcc.perfEvent import *

bpfPog = r"""
#include "lbc.h"

SEC("perf_event")
int bpf_prog(struct bpf_perf_event_data *ctx)
{
    bpf_printk("break point\n");
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CperfBreakPoint(ClbcBase):
    def __init__(self, pid, addr):
        super(CperfBreakPoint, self).__init__("perfBp", bpf_str=bpfPog)
        self._pid = pid
        self._addr = addr

    def loop2(self):
        print(self._pid, self._addr)
        pfConfig = {
            "type": PerfType.BREAKPOINT,
            "size": PERF_ATTR_SIZE_VER5,
            "sample_period": 1,
            "precise_ip": 2,
            "wakeup_events": 1,
            "bp_type": PerfBreakPointType.X,
            "bp_addr": self._addr,
            "bp_len": 8,
        }
        self.attachPerfEvent("bpf_prog", pfConfig, pid=self._pid, flags=PerfFlag.FD_CLOEXEC)
        pause()

    def loop3(self):
        print(self._pid, self._addr)
        pfConfig = {
            "type": PerfType.BREAKPOINT,
            "size": PERF_ATTR_SIZE_VER5,
            "sample_period": 1,
            "precise_ip": 2,
            "wakeup_events": 1,
            "bp_type": PerfBreakPointType.X,
            "bp_addr": self._addr,
            "bp_len": 8,
        }
        self.attachPerfEvent("bpf_prog", pfConfig, pid=self._pid, flags=PerfFlag.FD_CLOEXEC)
        pause()

    def loop1(self):
        print(self._pid, self._addr)
        pfConfig = {
            "type": PerfType.BREAKPOINT,
            "size": PERF_ATTR_SIZE_VER5,
            "disabled": 1,
            "inherit": 1,
            "exclude_guest": 1,
            "bp_type": PerfBreakPointType.X,
            "bp_addr": self._addr,
            "bp_len": 1,
        }
        self.attachPerfEvent("bpf_prog", pfConfig, pid=self._pid, flags=PerfFlag.FD_CLOEXEC)
        while True:
            time.sleep(1)


if __name__ == "__main__":
    pid = int(sys.argv[1])
    addr = int(sys.argv[2], 16)
    perf = CperfBreakPoint(pid, addr)
    perf.loop2()
    pass

