# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     irqoff
   Description :
   Author :       liaozhaoyan
   date：          2022/9/1
-------------------------------------------------
   Change Activity:
                   2022/9/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from signal import pause
from threading import Thread
from pylcc.lbcBase import ClbcBase, CeventThread
from pylcc.perfEvent import *

bpfPog = r"""
#include "lbc.h"

#define THRESHOLD_TIME (200 * 1000 * 1000ULL)
#define TASK_COMM_LEN 16
#define CON_NAME_LEN 80
struct data_t {
    int pid;
    u32 stack_id;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char con[CON_NAME_LEN];
};

LBC_PERCPU_ARRAY(perRec, int, u64, 2);
LBC_PERF_OUTPUT(e_sw, struct data_t, 16);
LBC_STACK(call_stack, 1024);

static void store_con(char* con, struct task_struct *p)
{
    struct kernfs_node *knode, *pknode;
    knode = BPF_CORE_READ(p, cgroups, subsys[0], cgroup, kn);
    pknode = BPF_CORE_READ(knode, parent);
    if (pknode != NULL) {
        char *name;
        bpf_core_read(&name, sizeof(void *), &knode->name);
        bpf_core_read(con, CON_NAME_LEN, name);
    } else {
        con[0] = '\0';
    }
}

static inline u64 get_last(int index) {
    u64 *pv = bpf_map_lookup_elem(&perRec, &index);
    if (pv) {
        return *pv;
    }
    return 0;
}

static inline void save_last(int index, u64 ns) {
    bpf_map_update_elem(&perRec, &index, &ns, BPF_ANY);
}

static inline void check_time(struct bpf_perf_event_data *ctx, 
                              int index,
                              struct bpf_map_def* event) {
    u64 ns = bpf_ktime_get_ns();
    u64 last = get_last(index);
    u64 delta;
    
    save_last(index, ns);
    delta = ns - last;
    if (last && delta >= THRESHOLD_TIME) {
        struct task_struct* task = bpf_get_current_task();
        struct data_t data = {};
        
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.stack_id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);
        data.delta = delta;
        bpf_get_current_comm(&data.comm, TASK_COMM_LEN);
        store_con(&data.con[0], task);
        
        bpf_perf_event_output(ctx, event, BPF_F_CURRENT_CPU, &data, sizeof(data));
    }
}

SEC("perf_event")
int sw_clock(struct bpf_perf_event_data *ctx)
{
    check_time(ctx, 1, &e_sw);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


THRESHOLD = 10 * 1000 * 1000  # 10ms


class CvirtOut(ClbcBase):
    def __init__(self):
        super(CvirtOut, self).__init__("virtout", bpf_str=bpfPog)

    def _setupSw(self):
        pfConfig = {
            "sample_period": THRESHOLD,
            "freq": 0,
            "type": PerfType.SOFTWARE,
            "config": PerfSwIds.CPU_CLOCK,
        }
        self.attachAllCpuPerf("sw_clock", pfConfig)
        CeventThread(self, 'e_sw', self._cb)

    def _cb(self, cpu, e):
        print("perf sw current pid:%d, comm:%s on: %d, delay %d ns" % (
            e.pid, e.comm, cpu, e.delta
        ))
        stacks = self.maps['call_stack'].getStacks(e.stack_id)
        print("call trace:")
        for s in stacks:
            print(s)

    def loop(self):
        self._setupSw()
        pause()


if __name__ == "__main__":
    i = CvirtOut()
    i.loop()
    pass
