# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     eventOut
   Description :
   Author :       liaozhaoyan
   date：          2021/11/3
-------------------------------------------------
   Change Activity:
                   2021/11/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os

from pylcc.lbcBase import ClbcBase, CeventThread
from surftrace.surfElf import CelfKsym
from pylcc.lbcStack import getKStacks

bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct data_t {
    u32 c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
    u32 stack_id;
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
LBC_STACK(call_stack,32);
SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct data_t data = {};

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    data.stack_id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);

    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CcallStack(ClbcBase):
    def __init__(self):
        super(CcallStack, self).__init__("callStack", bpf_str=bpfPog)
        self._ksym = CelfKsym()

    def _cb(self, cpu, e):
        print("cpu: %d current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            cpu, e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

        stacks = getKStacks(self.maps['call_stack'], e.stack_id, self._ksym)
        print("call trace:")
        for s in stacks:
            print(s)

    def loop(self):
        CeventThread(self, 'e_out', self._cb)
        self.waitInterrupt()


if __name__ == "__main__":
    e = CcallStack()
    e.loop()
