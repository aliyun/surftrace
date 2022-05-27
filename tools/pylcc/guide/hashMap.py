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

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
LBC_HASH(pid_cnt, u32, u32, 1024);
SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    u32 pid = BPF_CORE_READ(parent, pid);
    u32 *pcnt, cnt;
    
    pcnt =  bpf_map_lookup_elem(&pid_cnt, &pid);
    cnt  = pcnt ? *pcnt + 1 : 1;
    bpf_map_update_elem(&pid_cnt, &pid, &cnt, BPF_ANY);

    struct data_t data = {};
    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

class ChashMap(ClbcBase):
    def __init__(self):
        super(ChashMap, self).__init__("hashMap", bpf_str=bpfPog)

    def _cb(self, cpu, data, size):
        e = self.getMap('e_out', data, size)
        print("current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            dMap = self.maps['pid_cnt']
            print(dMap.get())
            exit()

if __name__ == "__main__":
    e = ChashMap()
    e.loop()
