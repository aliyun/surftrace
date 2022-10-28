# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     bindsnoop
   Description :
   Author :       liaozhaoyan
   date：          2022/8/7
-------------------------------------------------
   Change Activity:
                   2022/8/7:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import argparse
from pylcc.lbcBase import ClbcBase

# arguments
examples = """examples:
    ./bindsnoop           # trace all TCP bind()s
    ./bindsnoop -t        # include timestamps
    ./bindsnoop -w        # wider columns (fit IPv6)
    ./bindsnoop -p 181    # only trace PID 181
    ./bindsnoop -P 80     # only trace port 80
    ./bindsnoop -P 80,81  # only trace port 80 and 81
    ./bindsnoop -U        # include UID
    ./bindsnoop -u 1000   # only trace UID 1000
    ./bindsnoop -E        # report bind errors
    ./bindsnoop --count   # count bind per src ip
    ./bindsnoop --cgroupmap mappath  # only trace cgroups in this BPF map
    ./bindsnoop --mntnsmap  mappath  # only trace mount namespaces in the map
it is reporting socket options set before the bins call
impacting system call behavior:
 SOL_IP     IP_FREEBIND              F....
 SOL_IP     IP_TRANSPARENT           .T...
 SOL_IP     IP_BIND_ADDRESS_NO_PORT  ..N..
 SOL_SOCKET SO_REUSEADDR             ...R.
 SOL_SOCKET SO_REUSEPORT             ....r
 SO_BINDTODEVICE interface is reported as "IF" index
"""

struct_init = {
    'ipv4': {
        'count': r"""
               u64 k;
               u32 saddr;
               
               saddr = BPF_CORE_READ(psock, __sk_common.skc_rcv_saddr); // skp->__sk_common.skc_rcv_saddr;
               k = ((u64)sport << 32) | saddr;
               incr_hist(&ipv4_count, k);""",
        'trace': r"""
               struct ipv4_bind_data_t data4 = {.pid = pid, .ip = ipver};
               data4.uid = bpf_get_current_uid_gid();
               data4.ts_us = bpf_ktime_get_ns() / 1000;
               data4.saddr = BPF_CORE_READ(pinetsock, inet_saddr);
               data4.return_code = ret;
               data4.sport = sport;
               data4.bound_dev_if = BPF_CORE_READ(psock, __sk_common.skc_bound_dev_if); // psock->__sk_common.skc_bound_dev_if;
               data4.socket_options = opts.data;
               data4.protocol = BPF_CORE_READ_BITFIELD_PROBED(psock, sk_protocol);;
               bpf_get_current_comm(&data4.task, sizeof(data4.task));
               bpf_perf_event_output(ctx, &ipv4_bind_events, BPF_F_CURRENT_CPU, &data4, sizeof(data4));
               """
    },
}

bpfProg = r"""
#include "lbc.h"

#define TASK_COMM_LEN 16

LBC_HASH(currsock, u32, void *, 1024);

// bind options for event reporting
union bind_options {
    u8 data;
    struct {
        u8 freebind:1;
        u8 transparent:1;
        u8 bind_address_no_port:1;
        u8 reuseaddress:1;
        u8 reuseport:1;
    } fields;
};

struct ipv4_bind_data_t {
    u64 ts_us;
    u32 pid;
    u32 uid;
    u64 ip;
    u32 saddr;
    u32 bound_dev_if;
    int return_code;
    u16 sport;
    u8 socket_options;
    u8 protocol;
    char task[TASK_COMM_LEN];
};
LBC_PERF_OUTPUT(ipv4_bind_events, struct ipv4_bind_data_t, 128);

// separate flow keys per address family
struct ipv4_flow_key_t {
    u32 saddr;
    u16 sport;
};
LBC_HASH(ipv4_count, u64, u32, 1 * 1024);

SEC("kprobe/inet_bind")
int j_inet_bind(struct pt_regs *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    FILTER_PID
    u32 uid = bpf_get_current_uid_gid();
    FILTER_UID
    // stash the sock ptr for lookup on return
    struct socket *psocket = (struct socket *)PT_REGS_PARM1(ctx);
    bpf_map_update_elem(&currsock, &tid, &psocket, BPF_ANY);
    
    return 0;
}

static inline int bindsnoop_return(struct pt_regs *ctx, int ipver)
{
    int ret = PT_REGS_RC(ctx);
    int rv = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = pid_tgid;
    
    struct socket **ppsocket;
    ppsocket = (struct socket **)bpf_map_lookup_elem(&currsock, &tid);
    if (ppsocket == 0) {
        goto end_return;
    }
    int ignore_errors = 1;
    FILTER_ERRORS
    if (ret != 0 && ignore_errors) {
        // failed to bind
        goto end_delete;
    }
    // pull in details
    struct socket *psocket = *ppsocket;
    if (psocket == NULL) {
        goto end_delete;
    }
    struct sock *psock = BPF_CORE_READ(psocket, sk);
    if (psock == NULL) {
        goto end_delete;
    }
    struct inet_sock *pinetsock = (struct inet_sock *)psock;
    
    u16 sport = 0;
    sport = BPF_CORE_READ(pinetsock, inet_sport);
    sport = ntohs(sport);
    FILTER_PORT

    // fetching freebind, transparent, and bind_address_no_port bitfields
    // via the next struct member, rcv_tos
    
    union bind_options opts = {0};
    u8 freebind, transparent, bind_address_no_port, reuseaddress, reuseport, flag = 0;
    opts.fields.freebind = BPF_CORE_READ_BITFIELD_PROBED(pinetsock, freebind);
    opts.fields.transparent = BPF_CORE_READ_BITFIELD_PROBED(pinetsock, transparent);
    opts.fields.bind_address_no_port = BPF_CORE_READ_BITFIELD_PROBED(pinetsock, bind_address_no_port);
    opts.fields.reuseaddress = BPF_CORE_READ_BITFIELD_PROBED(pinetsock, sk.__sk_common.skc_reuse) & 0x01;
    opts.fields.reuseport = BPF_CORE_READ_BITFIELD_PROBED(pinetsock, sk.__sk_common.skc_reuseport);
    
    if (ipver == 4) {
        IPV4_CODE
    } else /* 6 */ {
        ;
    }
end_delete:
    bpf_map_delete_elem(&currsock, &tid);
end_return:
    return rv;
}

SEC("kretprobe/inet_bind")
int r_inet_bind(struct pt_regs *ctx) {
    return bindsnoop_return(ctx, 4);
}

char _license[] SEC("license") = "GPL";
"""


class Cbindsnoop(ClbcBase):
    def __init__(self, proj):
        super(Cbindsnoop, self).__init__("bindsnoopc", bpf_str=proj)

    def _cb(self, cpu, data, size):
        e = self.getMap('ipv4_bind_events', data, size)
        print(e.socket_options, e.pid, e.ip, e.sport)

    def loop(self):
        self.maps['ipv4_bind_events'].open_perf_buffer(self._cb)
        try:
            self.maps['ipv4_bind_events'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()

    def _showMaps(self):
        maps = self.maps['ipv4_count'].get()
        print(maps)

    def loopCount(self):
        self.waitInterrupt(self._showMaps)
        pass


def setupProg(args, prog):
    repDict = {
        "IPV4_CODE": struct_init['ipv4']['trace'],
        "FILTER_PID": "",
        "FILTER_PORT": "",
        "FILTER_UID": "",
        "FILTER_ERRORS": "",
    }

    if args.count:
        repDict['IPV4_CODE'] = struct_init['ipv4']['count']
    if args.pid:
        repDict['FILTER_PID'] = 'if (pid != %s) { return 0; }' % args.pid
    if args.port:
        sports = [int(sport) for sport in args.port.split(',')]
        sports_if = ' && '.join(['sport != %d' % sport for sport in sports])
        repDict['FILTER_PORT'] = 'if (%s) { bpf_map_delete_elem(&currsock, &tid); return 0; }' % sports_if
    if args.uid:
        repDict['FILTER_UID'] = 'if (uid != %s) { return 0; }' % args.uid
    if args.errors:
        repDict['FILTER_ERRORS'] = 'ignore_errors = 0;'

    for k, v in repDict.items():
        prog = prog.replace(k, v)
    return prog


def setupArgs():
    parser = argparse.ArgumentParser(
        description="Trace TCP binds",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-t", "--timestamp", action="store_true",
                        help="include timestamp on output")
    parser.add_argument("-w", "--wide", action="store_true",
                        help="wide column output (fits IPv6 addresses)")
    parser.add_argument("-p", "--pid",
                        help="trace this PID only")
    parser.add_argument("-P", "--port",
                        help="comma-separated list of ports to trace.")
    parser.add_argument("-E", "--errors", action="store_true",
                        help="include errors in the output.")
    parser.add_argument("-U", "--print-uid", action="store_true",
                        help="include UID on output")
    parser.add_argument("-u", "--uid",
                        help="trace this UID only")
    parser.add_argument("--count", action="store_true",
                        help="count binds per src ip and port")
    parser.add_argument("--cgroupmap",
                        help="trace cgroups in this BPF map only")
    parser.add_argument("--mntnsmap",
                        help="trace mount namespaces in this BPF map only")
    parser.add_argument("--ebpf", action="store_true",
                        help=argparse.SUPPRESS)
    parser.add_argument("--debug-source", action="store_true",
                        help=argparse.SUPPRESS)
    return parser.parse_args()


if __name__ == "__main__":
    args = setupArgs()
    prog = setupProg(args, bpfProg)
    if args.ebpf:
        print(prog)
    app = Cbindsnoop(prog)
    if args.count:
        app.loopCount()
    else:
        app.loop()



