# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     lccStream
   Description :
   Author :       liaozhaoyan
   date：          2022/12/13
-------------------------------------------------
   Change Activity:
                   2022/12/13:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import datetime
import time

from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct data_t {
    u32 c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

LBC_HASH(pid_cnt, int, struct data_t, 4);
SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    int i = 1;
    
    struct data_t data = {};
    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    
    bpf_map_update_elem(&pid_cnt, &i, &data, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class ClccStream(ClbcBase):
    def __init__(self):
        super(ClccStream, self).__init__("lccstream", bpf_str=bpfPog)

    def loop(self):
        d = {}
        while len(d) == 0:
            d = self.maps['pid_cnt'].get()
            time.sleep(1)

        print("begin.")
        t1 = datetime.datetime.now()
        for i in range(1000000):
            self.maps['pid_cnt'].get()
        t2 = datetime.datetime.now()
        print(t2 - t1)


if __name__ == "__main__":
    lcc = ClccStream()
    lcc.loop()
    pass
