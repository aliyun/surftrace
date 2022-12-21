# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     bccStream
   Description :
   Author :       liaozhaoyan
   date：          2022/12/13
-------------------------------------------------
   Change Activity:
                   2022/12/13:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
import datetime

from bcc import BPF

bpfPorg = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define TASK_COMM_LEN 16
struct data_t {
    long c_pid;
    u32 p_pid;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

BPF_HASH(pid_cnt, int, struct data_t, 4);

int j_wake_up_new_task(struct pt_regs *ctx, struct task_struct* parent)
{
    int i = 1;
    
    struct data_t data = {};
    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = parent->pid;
    bpf_probe_read_kernel(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    
    pid_cnt.update(&i, &data);
    return 0;
}
"""

b = BPF(text=bpfPorg)
b.attach_kprobe(event="wake_up_new_task", fn_name="j_wake_up_new_task")

d = {}
while len(d) == 0:
    time.sleep(1)
    d = b.get_table("pid_cnt")

print("begin.")
t1 = datetime.datetime.now()
for i in range(1000000):
    d = b.get_table("pid_cnt")    # if use b["pid_cnt"], bcc will read data from cache, not c stream.
t2 = datetime.datetime.now()
print(t2 - t1)

if __name__ == "__main__":
    pass
