# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     fileslower
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
import time
from pylcc.lbcBase import ClbcBase, CeventThread

bpfProg = r"""
#include "lbc.h"
#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_ISREG(m)      (((m) & S_IFMT) == S_IFREG)

#define TASK_COMM_LEN 16
#define DNAME_INLINE_LEN 32

enum trace_mode {
    MODE_READ,
    MODE_WRITE
};

struct val_t {
    u32 sz;
    u64 ts;
    u32 name_len;
    // de->d_name.name may point to de->d_iname so limit len accordingly
    char name[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
};

struct data_t {
    int mode;
    u32 pid;
    u32 sz;
    u64 delta_us;
    u32 name_len;
    char name[DNAME_INLINE_LEN];
    char comm[TASK_COMM_LEN];
};

LBC_HASH(entryinfo, u32, struct val_t, 1024);
LBC_PERF_OUTPUT(events, struct data_t, 128);

// store timestamp and size on entry
static int trace_rw_entry(struct pt_regs *ctx, struct file *file, size_t count)
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (TGID_FILTER)
        return 0;

    u32 pid = bpf_get_current_pid_tgid();

    // skip I/O lacking a filename
    struct dentry *de = BPF_CORE_READ(file, f_path.dentry); //file->f_path.dentry;
    int mode = BPF_CORE_READ(file, f_inode, i_mode);  //file->f_inode->i_mode;
    if (BPF_CORE_READ(de, d_name.len) == 0 || TYPE_FILTER)  //(de->d_name.len == 0 || TYPE_FILTER)
        return 0;

    // store size and timestamp by pid
    struct val_t val = {};
    val.sz = count;
    val.ts = bpf_ktime_get_ns();

    struct qstr d_name = BPF_CORE_READ(de, d_name);  //de->d_name;
    val.name_len = d_name.len;
    bpf_probe_read_kernel(&val.name, sizeof(val.name), d_name.name);
    bpf_get_current_comm(&val.comm, sizeof(val.comm));
    bpf_map_update_elem(&entryinfo, &pid, &val, BPF_ANY); //entryinfo.update(&pid, &val);

    return 0;
}

SEC("kprobe/__vfs_read")
int j__vfs_read(struct pt_regs *ctx)
{
    // skip non-sync I/O; see kernel code for __vfs_read()
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    if (!BPF_CORE_READ(file, f_op, read_iter))// (!(file->f_op->read_iter))
        return 0;
    return trace_rw_entry(ctx, file, count);
}

SEC("kprobe/__vfs_write")
int j__vfs_write(struct pt_regs *ctx)
{
    // skip non-sync I/O; see kernel code for __vfs_write()
    struct file *file = (struct file *)PT_REGS_PARM1(ctx);
    size_t count = PT_REGS_PARM3(ctx);
    if (!BPF_CORE_READ(file, f_op, read_iter))// (!(file->f_op->read_iter))
        return 0;
    return trace_rw_entry(ctx, file, count);
}

// output
static int trace_rw_return(struct pt_regs *ctx, int type)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();

    valp = bpf_map_lookup_elem(&entryinfo, &pid); // entryinfo.lookup(&pid);
    if (valp == 0) {
        // missed tracing issue or filtered
        return 0;
    }
    u64 delta_us = (bpf_ktime_get_ns() - valp->ts) / 1000;
    bpf_map_delete_elem(&entryinfo, &pid); // entryinfo.delete(&pid);
    if (delta_us < MIN_US)
        return 0;

    struct data_t data = {};
    data.mode = type;
    data.pid = pid;
    data.sz = valp->sz;
    data.delta_us = delta_us;
    data.name_len = valp->name_len;
    bpf_probe_read_kernel(&data.name, sizeof(data.name), valp->name);
    bpf_probe_read_kernel(&data.comm, sizeof(data.comm), valp->comm);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data)); // events.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

SEC("kretprobe/__vfs_read")
int r__vfs_read(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_READ);
}

SEC("kretprobe/__vfs_write")
int r__vfs_write(struct pt_regs *ctx)
{
    return trace_rw_return(ctx, MODE_WRITE);
}
char _license[] SEC("license") = "GPL";
"""

mode_s = {
    0: 'R',
    1: 'W',
}
start_ts = time.time()


class CfileSlower(ClbcBase):
    def __init__(self):
        super(CfileSlower, self).__init__("fileslower", bpf_str=bpfProg)
        print("Tracing sync read/writes slower than %d ms" % min_ms)
        print("%-8s %-14s %-6s %1s %-7s %7s %s" % ("TIME(s)", "COMM", "TID", "D",
                                                   "BYTES", "LAT(ms)", "FILENAME"))

    def _cb(self, cpu, e):
        ms = float(e.delta_us) / 1000
        name = e.name
        print("%-8.3f %-14.14s %-6s %1s %-7s %7.2f %s" % (
            time.time() - start_ts, e.comm,
            e.pid, mode_s[e.mode], e.sz, ms, name))

    def loop(self):
        CeventThread(self, 'events', self._cb)
        self.waitInterrupt()


if __name__ == "__main__":
    # arguments
    examples = """examples:
        ./fileslower             # trace sync file I/O slower than 10 ms (default)
        ./fileslower 1           # trace sync file I/O slower than 1 ms
        ./fileslower -p 185      # trace PID 185 only
    """
    parser = argparse.ArgumentParser(
        description="Trace slow synchronous file reads and writes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="tgid",
                        help="trace this PID only")
    parser.add_argument("-a", "--all-files", action="store_true",
                        help="include non-regular file types (sockets, FIFOs, etc)")
    parser.add_argument("min_ms", nargs="?", default='10',
                        help="minimum I/O duration to trace, in ms (default 10)")
    parser.add_argument("--ebpf", action="store_true",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()
    min_ms = int(args.min_ms)
    tgid = args.tgid
    debug = 1

    bpfProg = bpfProg.replace('MIN_US', str(min_ms * 1000))
    if args.tgid:
        bpfProg = bpfProg.replace('TGID_FILTER', 'tgid != %d' % tgid)
    else:
        bpfProg = bpfProg.replace('TGID_FILTER', '0')
    if args.all_files:
        bpfProg = bpfProg.replace('TYPE_FILTER', '0')
    else:
        bpfProg = bpfProg.replace('TYPE_FILTER', '!S_ISREG(mode)')

    if debug or args.ebpf:
        if args.ebpf:
            exit()

    f = CfileSlower()
    f.loop()
    pass
