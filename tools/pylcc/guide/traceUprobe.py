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

import time
import os
from pylcc.lbcBase import ClbcBase, CeventThread
from pylcc.lbcStack import ClbcUstack

bpfPog = r"""
#include "lbc.h"

struct data_t {
    u32 c_pid;
    u32 stack_id;
};

LBC_PERF_OUTPUT(e_out, struct data_t, 32);
LBC_STACK(call_stack,32);

SEC("uprobe/*")
int call_symbol(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    data.stack_id = bpf_get_stackid(ctx, &call_stack, USER_STACKID_FLAGS);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CtraceUprobe(ClbcBase):
    def __init__(self):
        super(CtraceUprobe, self).__init__("traceUprobe", bpf_str=bpfPog, attach=0)
        print(os.getpid())
        # self.attachUprobes("call_symbol", -1, "/usr/bin/bash", 567408)
        self.traceUprobes("call_symbol", -1, "./user:readline")

    def _cb(self, cpu, e):
        print("pool event cpu %d, pid:%d, stackid:%d" % (cpu, e.c_pid, e.stack_id))
        stacks = self.maps['call_stack'].getArr(e.stack_id)
        print(stacks)
        uStack = ClbcUstack(e.c_pid, stacks)
        print(uStack.dumpStacks())

    def loop(self):
        CeventThread(self, 'e_out', self._cb)
        self.waitInterrupt()


if __name__ == "__main__":
    u = CtraceUprobe()
    u.loop()
    pass

