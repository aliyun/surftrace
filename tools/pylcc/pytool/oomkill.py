import ctypes as ct
from pylcc.lbcBase import ClbcBase
from time import strftime

loadavg = "/proc/loadavg"
bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct data_t {
    u32 c_pid;
    u32 p_pid;
    u64 pages;
    char c_comm[TASK_COMM_LEN];
    char p_comm[TASK_COMM_LEN];
};

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
SEC("kprobe/oom_kill_process")
int j_oom_kill_process(struct pt_regs *ctx)
{
    struct oom_control* oc = (struct oom_control *)PT_REGS_PARM1(ctx);
    struct task_struct* parent;
    bpf_core_read(&parent, sizeof(parent), &oc->chosen);
    struct data_t data = {};

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    data.p_pid = BPF_CORE_READ(parent, pid);
    bpf_core_read(&data.pages, sizeof(data.pages), &oc->totalpages);
    bpf_core_read(&data.p_comm[0], TASK_COMM_LEN, &parent->comm[0]);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CeventOut(ClbcBase):
    def __init__(self):
        super(CeventOut, self).__init__("eventOut", bpf_str=bpfPog)

    def _cb(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['e_out'].event(stream)
        with open(loadavg) as stats:
            avgline = stats.read().rstrip()
        print(("%s Triggered by PID %d (\"%s\"), OOM kill of PID %d (\"%s\")"
               ", %d pages, loadavg: %s") % (
            strftime("%H:%M:%S"), e.c_pid, e.c_comm, e.p_pid, e.p_comm, e.pages, avgline))

    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()


if __name__ == "__main__":
    e = CeventOut()
    e.loop()
