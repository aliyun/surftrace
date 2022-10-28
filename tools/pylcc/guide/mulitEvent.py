# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     mulitEvent
   Description :
   Author :       liaozhaoyan
   date：          2022/8/31
-------------------------------------------------
   Change Activity:
                   2022/8/31:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from pylcc.lbcBase import ClbcBase, CeventThread

bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct data_t {
    u32 c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

LBC_PERF_OUTPUT(e1_out, struct data_t, 128);
LBC_PERF_OUTPUT(e2_out, struct data_t, 128);

SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct data_t data = {};

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);

    bpf_perf_event_output(ctx, &e1_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

SEC("kprobe/wake_up_process")
int j_wake_up_process(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    struct data_t data = {};

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);

    bpf_perf_event_output(ctx, &e2_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CmulitEvent(ClbcBase):
    def __init__(self):
        super(CmulitEvent, self).__init__("eventOut", bpf_str=bpfPog)

    def _cb_e1(self, cpu, e):
        print("e1: cpu: %d current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            cpu, e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def _cb_e2(self, cpu, e):
        print("e1: cpu: %d current pid:%d, comm:%s. wake_up_process pid: %d, comm: %s" % (
            cpu, e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def loop(self):
        CeventThread(self, "e1_out", self._cb_e1)
        CeventThread(self, "e2_out", self._cb_e2)
        self.waitInterrupt()


if __name__ == "__main__":
    m = CmulitEvent()
    m.loop()
    pass
