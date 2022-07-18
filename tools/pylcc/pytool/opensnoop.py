# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name:     filelife
   Description :
   Author :       xiugu.yh
   date:          2022/07/15
-------------------------------------------------
   Change Activity:
                   2022/07/15:
-------------------------------------------------
"""
__author__ = 'xiugu.yh'

import ctypes as ct
import argparse
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 32

struct data_t {
    u32 ret;
    u64 start_ts;
    u64 end_ts;
    u32 c_pid;
    u32 uid;
    char c_comm[TASK_COMM_LEN];
    char filename[FILE_NAME_LEN];
};

struct my_str {
    char filename[32];
};

LBC_HASH(entryinfo, u32, struct data_t, 1024);

LBC_PERF_OUTPUT(e_out, struct data_t, 128);
SEC("kprobe/do_sys_openat2")
int entry_do_sys_openat2(struct pt_regs *ctx)
{
    struct my_str dname = {};
    struct data_t data = {};
    const char *filename = (char *)PT_REGS_PARM2(ctx);

    data.c_pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid();
    data.start_ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void *)filename);

    bpf_map_update_elem(&entryinfo, &data.c_pid, &data, BPF_ANY);

    return 0;
}

SEC("kretprobe/do_sys_openat2")
int ret_do_sys_openat2(struct pt_regs *ctx)
{
    struct data_t data = {};
    data.ret = ctx->ax;

    data.c_pid = bpf_get_current_pid_tgid() >> 32;

    struct data_t *data_ret = bpf_map_lookup_elem(&entryinfo, &data.c_pid);
    if (data_ret == 0) {
        return 0;
    }

    PID_FILTER

    data.end_ts = bpf_ktime_get_ns();
    data.start_ts = data_ret->start_ts;
    data.uid = data_ret->uid;
    UID_FILTER
    DELTA_TIME_FILTER
    data.c_pid = data_ret->c_pid;
    bpf_probe_read_kernel(&data.filename, sizeof(data_ret->filename), (void *)data_ret->filename);
    // bpf_probe_read_kernel(&data.start_ts, sizeof(data_ret->start_ts), data_ret->start_ts);
    // bpf_probe_read_kernel(&data.c_pid, sizeof(data_ret->c_pid), data_ret->c_pid);


    bpf_get_current_comm(&data.c_comm, TASK_COMM_LEN);
    
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &data, sizeof(data));

    return 0;
}

char _license[] SEC("license") = "GPL";
"""

class OpenSnoop(ClbcBase):
    def __init__(self, args):
        super(OpenSnoop, self).__init__("OpenSnoop", bpf_str=bpfPog)
        self.args = args
        print("%-4s %-8s %-16s %-32s %16s %8s" % 
        ("UID", "PID", "COMM", "FILENAME", "DELTATIME(us)", "FD"))

    def _cb(self, cpu, data, size):
        e = self.getMap('e_out', data, size)
        if self.args.comm:
            if self.args.comm in e.c_comm:
                print("%-4s %-8d %-16s %-32s %16s %8s" % 
                (e.uid, e.c_pid, e.c_comm, e.filename, (int(e.end_ts) - int(e.start_ts))/1000, e.ret))
        else:
            print("%-4s %-8d %-16s %-32s %16s %8s" % 
            (e.uid, e.c_pid, e.c_comm, e.filename, (int(e.end_ts) - int(e.start_ts))/1000, e.ret))


    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()

if __name__ == "__main__":

    examples = """examples:
    ./opensnoop           # trace all open() syscalls
    ./opensnoop -p 1469   # only trace PID 1469
    ./opensnoop -c cat    # only trace process name contain cat
    ./opensnoop -d 10     # only print the delta time more than this threshold value
    ./opensnoop -u 1000   # only trace uid 1000
    """
    parser = argparse.ArgumentParser(
        description="Trace open() syscalls",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-p", "--pid", help="trace this PID only")
    parser.add_argument("-c", "--comm", help="only print process names containing this name")
    parser.add_argument("-d", "--delay", type=int, help="only print delta time more than this threshold value")
    parser.add_argument("-u", "--uid", type=int, help="trace this UID only")

    args = parser.parse_args()


    DELTA_TIME_FILTER = ''
    PID_FILTER = ''
    UID_FILTER = ''

    if args.pid:
        PID_FILTER = '''
        if(data.c_pid != %s) 
        {
            return 0;
        }
        ''' % args.pid
    
    if args.delay:
        DELTA_TIME_FILTER = '''
        if((data.end_ts - data.start_ts) / 1000 < %d)
        {
            return 0;
        }
        ''' % args.delay

    if args.uid:
        UID_FILTER = '''
        if(data.uid != %d)
        {
            return 0;
        }
        ''' % args.uid
    bpfPog = bpfPog.replace('PID_FILTER', PID_FILTER)
    bpfPog = bpfPog.replace('DELTA_TIME_FILTER', DELTA_TIME_FILTER)
    bpfPog = bpfPog.replace('UID_FILTER', UID_FILTER)

    e = OpenSnoop(args = args)
    e.loop()
