# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     filelife
   Description :
   Author :       liaozhaoyan
   date：          2021/11/6
-------------------------------------------------
   Change Activity:
                   2021/11/6:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import argparse
from time import strftime
from pylcc.lbcBase import ClbcBase, CeventThread

bpfProg = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16
#define DNAME_INLINE_LEN 32

struct data_t {
    u32 pid;
    u64 delta;
    char comm[TASK_COMM_LEN];
    char fname[DNAME_INLINE_LEN];
};

LBC_HASH(birth, struct dentry *, u64, 1024);
LBC_PERF_OUTPUT(events, struct data_t, 128);

// trace file creation time
SEC("kprobe/vfs_create")
int j_vfs_create(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    FILTER

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&birth, &dentry, &ts, BPF_ANY);
    return 0;
};

SEC("kprobe/security_inode_create")
int j_security_inode_create(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    FILTER

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&birth, &dentry, &ts, BPF_ANY);
    return 0;
};

// trace file deletion and output details
SEC("kprobe/vfs_unlink")
int j_vfs_unlink(struct pt_regs *ctx)
{
    struct data_t data = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct dentry *dentry = (struct dentry *)PT_REGS_PARM2(ctx);

    FILTER

    u64 *tsp, delta;
    tsp = bpf_map_lookup_elem(&birth, &dentry);
    if (tsp == 0) {
        return 0;   // missed create
    }

    delta = (bpf_ktime_get_ns() - *tsp) / 1000000;

    struct qstr d_name;
    d_name = BPF_CORE_READ(dentry, d_name);
    if (d_name.len == 0)
        return 0;

    if (bpf_get_current_comm(&data.comm, sizeof(data.comm)) == 0) {
        data.pid = pid;
        data.delta = delta;
        bpf_probe_read_kernel(&data.fname, sizeof(data.fname), d_name.name);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}
char _license[] SEC("license") = "GPL";
"""


class CfileLife(ClbcBase):
    def __init__(self):
        super(CfileLife, self).__init__("filelife", bpf_str=bpfProg)
        print("%-8s %-6s %-16s %-7s %s" % ("TIME", "PID", "COMM", "AGE(s)", "FILE"))

    def _cb(self, cpu, e):
        print("%-8s %-6d %-16s %-7.2f %s" % (strftime("%H:%M:%S"), e.pid,
                                             e.comm, float(e.delta) / 1000,
                                             e.fname))

    def loop(self):
        CeventThread(self, 'events', self._cb)
        self.waitInterrupt()


if __name__ == "__main__":
    # arguments
    examples = """examples:
        ./filelife           # trace all stat() syscalls
        ./filelife -p 181    # only trace PID 181
    """
    parser = argparse.ArgumentParser(
        description="Trace stat() syscalls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid",
                        help="trace this PID only")
    parser.add_argument("--ebpf", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    debug = 0

    if args.pid:
        bpfProg = bpfProg.replace('FILTER',
                                  'if (pid != %s) { return 0; }' % args.pid)
    else:
        bpfProg = bpfProg.replace('FILTER', '')
    if debug or args.ebpf:
        print(bpfProg)
        if args.ebpf:
            exit()

    f = CfileLife()
    f.loop()
