# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     perfMemFly
   Description :
   Author :       liaozhaoyan
   date：          2022/10/27
-------------------------------------------------
   Change Activity:
                   2022/10/27:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import json
from pylcc.lbcBase import ClbcBase, CeventThread
from surftrace.surfElf import CelfKsym
from pylcc.lbcStack import getKStacks
from pylcc.perfEvent import *

PROC_FILE = "/proc/coolbpf/sys_fly"


bpfPog = r"""
#include "lbc.h"
struct data_t {
    int pid;
    int stack_id;
    u64 ts;
    u64 addr;
    u64 value;
    char comm[16];
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
LBC_STACK(call_stack, 4096);

SEC("perf_event")
int bpf_prog(struct bpf_perf_event_data *ctx)
{
    struct data_t data = {};
    u64* addr = (u64*)(ctx->addr);
    
    data.stack_id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);
    data.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.comm, 16);
    
    data.ts = bpf_ktime_get_ns();
    data.addr = ctx->addr;
    data.value = _(*addr);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CperfMemFly(ClbcBase):
    def __init__(self):
        super(CperfMemFly, self).__init__("pMmeFly", bpf_str=bpfPog)
        addr = self._getAddr()
        self._setupPerf(addr)
        self._ksym = CelfKsym()

        self._lastTs = 0
        self._beg = 0
        self._lastD = {}
        self._arr = []

    @staticmethod
    def _getAddr():
        fd = os.open(PROC_FILE, os.O_RDWR)
        p, v = os.read(fd, 64).decode().split(':')
        os.close(fd)
        return int(p, 16)

    def _setupPerf(self, addr):
        pfConfig = {
            "type": PerfType.BREAKPOINT,
            "size": PERF_ATTR_SIZE_VER5,
            "sample_period": 1,
            "precise_ip": 2,
            "wakeup_events": 1,
            "bp_type": PerfBreakPointType.W,
            "bp_addr": addr,
            "bp_len": 8,
        }
        self.attachAllCpuPerf("bpf_prog", pfConfig, flags=PerfFlag.FD_CLOEXEC)

    def _cb(self, cpu, e):
        print("cpu %d, pid: %d, comm:%s" % (cpu, e.pid, e.comm))
        print("set addr 0x%x to %d in %d ns" % (e.addr, e.value, e.ts))
        stacks = getKStacks(self.maps['call_stack'], e.stack_id, self._ksym)
        print("call stack:")
        print("\t" + "\n\t".join(stacks))
        self._saveTrace(e)

    def _saveTrace(self, e):
        now = int(e.ts / 1000)
        if self._lastTs:
            self._lastD["ph"] = "E"
            self._lastD["ts"] = now - self._beg
            self._arr.append(self._lastD)
        else:
            self._beg = now

        d = {"name": str(e.value),
             "pid": "mem",
             "tid": "%s:%d" % (e.comm, e.pid),
             "ph": "B",
             "ts": now - self._beg,
             "args": {"stacks": "\n".join(getKStacks(self.maps['call_stack'], e.stack_id, self._ksym))}
             }
        self._arr.append(d)

        self._lastTs = now
        self._lastD = d.copy()
        del self._lastD["args"]

    def _cbExit(self):
        self._lastD["ph"] = "E"
        self._lastD["ts"] += 1
        self._arr.append(self._lastD)

        with open("mem.json", "w") as f:
            json.dump(self._arr, f)

    def loop(self):
        CeventThread(self, 'e_out', self._cb)
        self.waitInterrupt(self._cbExit)


if __name__ == "__main__":
    fly = CperfMemFly()
    fly.loop()
    pass
