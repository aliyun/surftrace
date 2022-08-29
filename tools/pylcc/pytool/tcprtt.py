# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name:     tcprtt
   Description :
   Author :       xiugu.yh
   date:          2022/07/26
-------------------------------------------------
   Change Activity:
                   2022/07/26:
-------------------------------------------------
"""
__author__ = 'xiugu.yh'

import ctypes as ct
import argparse
import time
from pylcc.lbcBase import ClbcBase
from socket import inet_ntop, inet_aton, ntohs, AF_INET, AF_INET6
from struct import pack, unpack

bpfPog = r"""
#include "lbc.h"

#define TASK_COMM_LEN 16
#define FILE_NAME_LEN 32
#define BUFFER_LEN 200

typedef struct sock_key {
    u32 saddr;
    u32 daddr;
    u64 slot;
    u16 sport;
    u16 dport;
    u16 family;
} sock_key_t;

typedef struct sock_latenty {
    u64 latency;
    u64 count;
} sock_latency_t;

LBC_HIST2(hist2);
LBC_HASH(start, u32, u64, 256 * 1024);  //record ns
SEC("kprobe/tcp_rcv_established")
int entry_tcp_rcv_established(struct pt_regs *ctx)
{
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct inet_sock *inet = (struct inet_sock *)sk;
    struct tcp_sock *ts = (struct tcp_sock *)sk;
    u32 srtt = 0;

    /* filters */
    u16 sport = 0;
    u16 dport = 0;
    u32 saddr = 0;
    u32 daddr = 0;
    u16 family = 0;

    bpf_probe_read_kernel(&srtt, sizeof(srtt), (void *)&ts->srtt_us);
    bpf_probe_read_kernel(&sport, sizeof(sport), (void *)&sk->__sk_common.skc_num);
    bpf_probe_read_kernel(&dport, sizeof(dport), (void *)&sk->__sk_common.skc_dport);
    bpf_probe_read_kernel(&saddr, sizeof(saddr), (void *)&sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&daddr, sizeof(daddr), (void *)&sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&family, sizeof(family), (void *)&sk->__sk_common.skc_family);

    LPORTFILTER
    RPORTFILTER
    LADDRFILTER
    RADDRFILTER

    // to ms
    srtt  = srtt >> 3; // us
    srtt /= 1000; // ms
    
    hist2_push(&hist2, srtt);
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

class TcpRtt(ClbcBase):
    def __init__(self, args):
        super(TcpRtt, self).__init__("TcpRtt", bpf_str=bpfPog)

    def proc(self):
        try:
            print("----------------------------\n")
            print("sport: %s  dport: %s  saddr: %s  daddr: %s" 
            %(args.lport, args.rport, args.laddr, args.raddr))
            print("ms\tcount\tdistribution")
            self.maps['hist2'].showHist("hist2:")
            print("----------------------------\n")
        except ValueError:
            print("The input list is empty or all zero.")

if __name__ == "__main__":

    examples = """examples:
    ./tcprtt            # summarize TCP RTT
    ./tcprtt -i 1 -d 10 # print 1 second summaries, 10 times
    ./tcprtt -p         # filter for local port
    ./tcprtt -P         # filter for remote port
    ./tcprtt -a         # filter for local address
    ./tcprtt -A         # filter for remote address
    ./tcprtt -b         # show sockets histogram by local address
    ./tcprtt -B         # show sockets histogram by remote address
    ./tcprtt -e         # show extension summary(average)
    """
    parser = argparse.ArgumentParser(
        description="Summarize TCP RTT as a histogram",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples)
    parser.add_argument("-i", "--interval", type=int, default=3, help="summary interval, seconds")
    parser.add_argument("-d", "--duration", type=int, default=99999, help="total duration of trace, seconds")
    parser.add_argument("-p", "--lport", type=int, help="filter for local port")
    parser.add_argument("-P", "--rport", type=int, help="filter for remote port")
    parser.add_argument("-a", "--laddr", help="filter for local address")
    parser.add_argument("-A", "--raddr", help="filter for remote address")
    # parser.add_argument("-b", "--byladdr", action="store_true", help="show sockets histogram by local address")
    # parser.add_argument("-B", "--byraddr", action="store_true", help="show sockets histogram by remote address")


    args = parser.parse_args()

    LPORTFILTER = ''
    RPORTFILTER = ''
    LADDRFILTER = ''
    RADDRFILTER = ''
    

    if args.lport:
        LPORTFILTER = '''
        if (sport != %d)
        {
            return 0;
        }
        ''' % args.lport

    if args.rport:
        RPORTFILTER = '''
        if (dport != %d)
        {
            return 0;
        }
        ''' % ntohs(args.rport)
    
    if args.laddr:
        LADDRFILTER = '''
        if (saddr != %d)
        {
            return 0;
        }
        ''' % unpack("=I", inet_aton(args.laddr))[0]
    if args.raddr:
        RADDRFILTER = '''
        if (daddr != %d)
        {
            return 0;
        }
        ''' % unpack("=I", inet_aton(args.raddr))[0]
    
    bpfPog = bpfPog.replace('LPORTFILTER', LPORTFILTER)
    bpfPog = bpfPog.replace('RPORTFILTER', RPORTFILTER)
    bpfPog = bpfPog.replace('LADDRFILTER', LADDRFILTER)
    bpfPog = bpfPog.replace('RADDRFILTER', RADDRFILTER)


    e = TcpRtt(args)
    for i in range(args.duration):
        time.sleep(args.interval)
        e.proc()
