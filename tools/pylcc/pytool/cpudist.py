# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     cpudist.py
   Description :
   Author :       liaozhaoyan
   date：          2022/5/12
-------------------------------------------------
   Change Activity:
                   2022/5/12:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
from pylcc.lbcBase import ClbcBase

DIST_ARRAYS = 8

bpfProg = r"""
#include "lbc.h"


LBC_HIST2(hist2);
LBC_HIST10(hist10);
LBC_HASH(start, u32, u64, 256 * 1024);  //record ns

struct sched_switch_args {
    u16 type;
    u8  flag;
    u8  preeempt;
    u32 c_pid;
    char prev_comm[16];
    u32  prev_pid;
    u32 prev_prio;
    u64 prev_state;
    char next_comm[16];
    u32  next_pid;
    u32 next_prio;
};
SEC("tracepoint/sched/sched_switch")
int sched_switch_hook(struct sched_switch_args *args){
    u64 ts = bpf_ktime_get_ns();
    u64 *pv;
    u32 prev = args->prev_pid;
    u32 next = args->next_pid;

    bpf_map_update_elem(&start, &next, &ts, BPF_ANY);
    pv = bpf_map_lookup_elem(&start, &prev);
    if (pv && ts > *pv) {
        hist10_push(&hist10, ts- *pv);
        hist2_push(&hist2, ts- *pv);
    }
}

char _license[] SEC("license") = "GPL";
"""


class Ccpudist(ClbcBase):
    def __init__(self):
        super(Ccpudist, self).__init__("cpudist", bpf_str=bpfProg)

    def proc(self):
        self.maps['hist2'].showHist("hist2:")
        print
        self.maps['hist10'].showHist("hist10:")


if __name__ == "__main__":
    dist = Ccpudist()
    while True:
        time.sleep(5)
        dist.proc()
