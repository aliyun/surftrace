from __future__ import print_function
from pylcc.lbcBase import ClbcBase
import sys

bpfPog = """
    #include "lbc.h"
    struct data_t {
        u64 ts;
    };
    LBC_PERF_OUTPUT(e_out, struct data_t, 128);
    SEC("tracepoint/syscalls/sys_enter_open")
    int trace_enter_open(struct syscalls_enter_open_args *ctx)
    {
        struct data_t data = {};
        data.ts = bpf_ktime_get_ns() / 1000;
        bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));
    };
    char _license[] SEC("license") = "GPL";
"""
class CeventOut(ClbcBase):
    def __init__(self):
        super(CeventOut, self).__init__("eventOut", bpf_str=bpfPog)

    def _cb(self, cpu, data, size):
        event = self.getMap('e_out', data, size)
        print("%-18.9f sync()" % (float(event.ts) / 1000000))
        sys.stdout.flush()

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
