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

LBC_ARRAY(cpudist, int, u64, 8);
/*
unit us;
0-1:
1-10:
10-100:
100-1k:
1k-10k:
10k-100k:
100k-1M:
>1M
*/
LBC_HASH(start, u32, u64, 256 * 1024);  //record ns

static inline void addDist(int k) {
    u64 *pv = bpf_map_lookup_elem(&cpudist, &k);
    if (pv) {
        __sync_fetch_and_add(pv, 1);
    }
}

static inline void checkUs(u64 delta) {
    if (delta < 1) {
        addDist(0);
    } else if (delta < 10) {
        addDist(1);
    } else if (delta < 100) {
        addDist(2);
    } else if (delta < 1000) {
        addDist(3);
    } else if (delta < 10000) {
        addDist(4);
    } else if (delta < 100000) {
        addDist(5);
    } else if (delta < 1000000) {
        addDist(6);
    } else {
        addDist(7);
    }
}

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
        checkUs((ts - *pv) / 1000);
    }
}

char _license[] SEC("license") = "GPL";
"""


class Ccpudist(ClbcBase):
    def __init__(self):
        super(Ccpudist, self).__init__("cpudist", bpf_str=bpfProg)
        self._rec = [0] * DIST_ARRAYS

    def _get(self):
        a = []
        for i in range(DIST_ARRAYS):
            a.append(self.maps['cpudist'].getKeyValue(i))
        return a

    def proc(self):
        g = self._get()
        res = []
        for i in range(DIST_ARRAYS):
            res.append(g[i] - self._rec[i])
        self._rec = g
        return res


if __name__ == "__main__":
    dist = Ccpudist()
    while True:
        time.sleep(5)
        print(dist.proc())
