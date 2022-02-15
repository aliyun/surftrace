
# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     runlatency
   Description :
   Author :       liaozhaoyan
   date：          2021/11/28
-------------------------------------------------
   Change Activity:
                   2021/11/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import argparse
import ctypes as ct
import sys
from time import strftime
from pylcc.lbcBase import ClbcBase, CexecCmd

bpfProg = r"""
#include "lbc.h"
struct data_t {
    int cpu;
    int type;   // 0: irq, 1:sirq
    u32 stack_id;
    u64 delayed;
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
LBC_STACK(call_stack, 256);

// check_timer_delay(bool hirq, int cpu , u64 delta, u64 stamp)
SEC("kprobe/check_timer_delay")
int j_check_timer_delay(struct pt_regs *ctx)
{
    struct data_t data = {};
    
    data.cpu = PT_REGS_PARM2(ctx);
    data.type = PT_REGS_PARM1(ctx);
    data.delayed = PT_REGS_PARM3(ctx);
    data.stack_id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}
char _license[] SEC("license") = "GPL";
"""

class Crunlatency(ClbcBase):
    def __init__(self, lat=10):
        self._exec = CexecCmd
        self.setupKo(lat >> 1)
        super(Crunlatency, self).__init__("runlatency", server="172.24.90.148", bpf_str=bpfProg)

    def checkKoInstall(self, ko):
        installed = False
        mods = self._exec.cmd("lsmod")
        for mod in mods.split('\n'):
            if mod.startswith(ko):
                installed = True
                break
        if not installed:
            self._exec.cmd("insmod %s.ko" % ko)

    def setupKo(self, lat):
        self.checkKoInstall("runlat")
        enable = self._exec.cmd("cat /proc/runlatency/enable")
        if enable[0] == '1':
            self._exec.system("echo 0 > /proc/runlatency/enable")
        print("setup ko")
        self._exec.system("echo %d > /proc/runlatency/period" % int(lat))
        self._exec.system("echo 1 > /proc/runlatency/enable")

    def releaseKo(self):
        self._exec.system("echo 0 > /proc/runlatency/enable")

    def _cb(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['e_out'].event(stream)
        print(e.type)
        if e.type == 1:
            print("cpu%d catch %dns hard irq delay." % (e.cpu, e.delayed))
        else:
            print("cpu%d catch %dns soft irq delay." % (e.cpu, e.delayed))
        stacks = self.maps['call_stack'].getStacks(e.stack_id)
        for s in stacks:
            print(s)

    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            self.releaseKo()
            exit()

if __name__ == "__main__":
    lat = 10
    if len(sys.argv) >= 2:
        lat = int(sys.argv[1])
    run = Crunlatency(lat)
    run.loop()

