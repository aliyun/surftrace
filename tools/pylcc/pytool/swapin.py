import ctypes as ct
from pylcc.lbcBase import ClbcBase
from time import sleep, strftime

interval = 1
bpfPog = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
struct key_t {
    u64 count;
    char comm[TASK_COMM_LEN];
};

LBC_HASH(counts,u32, struct key_t, 1024);
SEC("kprobe/swap_readpage")
int j_swap_readpage(struct pt_regs *ctx)
{
    u64 *val, cnt;
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct key_t key;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    val =  bpf_map_lookup_elem(&counts, &tgid);
    cnt  = val ? *val + 1 : 1;
    key.count = cnt;
    bpf_map_update_elem(&counts, &tgid, &key, BPF_ANY);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class ChashMap(ClbcBase):
    def __init__(self):
        super(ChashMap, self).__init__("hashMap", bpf_str=bpfPog)

    def loop(self):
        print("Counting swap ins. Ctrl-C to end.")
        while 1:
            try:
                sleep(interval)
            except KeyboardInterrupt:
                print("Detaching...")
                exit()
            print(strftime("%H:%M:%S"))
            print("%-16s %-7s %s" % ("COMM", "PID", "COUNT"))
            dMap = self.maps['counts']
            dict = dMap.get()
            for k, v in sorted(dict.items(),
                               key=lambda counts: counts[1]['count']):
                print("%-16s %-7d %d" % (v['comm'], k, v['count']))
            dMap.clear()
            print()


if __name__ == "__main__":
    e = ChashMap()
    e.loop()
