#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ipTop
   Description :
   Author :       liaozhaoyan
   date：          2022/8/30
-------------------------------------------------
   Change Activity:
                   2022/8/30:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
import tty
import termios
import socket
import struct
import atexit
from threading import Thread
from collections import Counter
from pylcc.lbcBase import ClbcBase

if sys.version_info.major > 2:
    from queue import Queue, Empty
else:
    from Queue import Queue, Empty

bpfPog = r"""
#include "lbc.h"

LBC_HASH(ip_src_bytes, u32, u64, 256);
LBC_HASH(ip_src_packs, u32, u64, 256);
LBC_HASH(dst_bytes, u32, u64, 256);
LBC_HASH(ip_dst_packs, u32, u64, 256);

static inline void add_ip_maps(struct bpf_map_def* maps, u32 k, u64 v) {
    u64 *pv = bpf_map_lookup_elem(maps, &k);
    if (pv) {
        __sync_fetch_and_add(pv, v);
    }
    else {
        bpf_map_update_elem(maps, &k, &v, BPF_ANY);
    }
}

static inline struct ethhdr *get_ethhdr(struct sk_buff *skb) {
    void* head;
    u16 offset;
    struct ethhdr *pethhdr;
    
    head = (void*)BPF_CORE_READ(skb, head);
    offset = BPF_CORE_READ(skb, mac_header);
    pethhdr = (struct ethhdr *)(head + offset);
    return pethhdr;
}

static inline struct iphdr *get_iphdr(struct sk_buff *skb) {
    void* head;
    u16 offset;
    struct iphdr *piphr;
    
    head = (void*)BPF_CORE_READ(skb, head);
    offset = BPF_CORE_READ(skb, network_header);
    piphr = (struct iphdr *)(head + offset);
    return piphr;
}

SEC("kprobe/ip_rcv")
int j_ip_rcv(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct iphdr *piphr = get_iphdr(skb);
    u32 src = BPF_CORE_READ(piphr, saddr);
    u32 len = BPF_CORE_READ(skb, len);
    
    add_ip_maps(&ip_src_bytes, src, len);
    add_ip_maps(&ip_src_packs, src, 1);
    return 0;
}

SEC("kprobe/dev_queue_xmit_nit")
int j_ip_out(struct pt_regs *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)PT_REGS_PARM1(ctx);
    struct ethhdr *pethhdr = get_ethhdr(skb);
    u16 proto = BPF_CORE_READ(pethhdr, h_proto);
    if (proto == 0x0008)
    {
        struct iphdr *piphr = get_iphdr(skb);
        u32 dst = BPF_CORE_READ(piphr, daddr);
        u32 len = BPF_CORE_READ(skb, len);
    
        add_ip_maps(&dst_bytes, dst, len);
        add_ip_maps(&ip_dst_packs, dst, 1);
    }
    else {
        bpf_printk("proto: %x\n", proto);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

old_setting = termios.tcgetattr(sys.stdin.fileno())


def save_old_settings():
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_setting)


class CinputThread(Thread):
    def __init__(self, q):
        super(CinputThread, self).__init__()
        self.setDaemon(True)
        self._q = q

        self.start()

    def _putch(self, ch):
        chs = ('T', 't', 'R', 'r', 'D', 'd', 'q', 'Q')
        try:
            i = chs.index(ch)
        except ValueError:
            return
        self._q.put(i)

    def run(self):
        tty.setraw(sys.stdin.fileno(), termios.TCSANOW)
        while True:
            ch = sys.stdin.read(1)
            self._putch(ch)
            if ch.lower() == 'q':
                break


class CipTop(ClbcBase):
    def __init__(self):
        super(CipTop, self).__init__("iptop", bpf_str=bpfPog)
        self._q = Queue(maxsize=16)

        self._t = CinputThread(self._q)

    def _dictPack(self, a, b):
        return dict(Counter(a) + Counter(b))

    def _collect(self):
        res = []
        cList = ("dst_bytes", "ip_dst_packs", "ip_src_bytes", "ip_src_packs")
        for c in cList:
            res.append(self.maps[c].get())
            self.maps[c].clear()
        res.append(self._dictPack(res[0], res[2]))
        res.append(self._dictPack(res[1], res[3]))
        return res

    def loop(self):
        choose = 0
        titles = (
            "send bytes\r\nip\t\tbytes\r",
            "send packs\r\nip\t\tpacks\r",
            "recv bytes\r\nip\t\tbytes\r",
            "recv packs\r\nip\t\tpacks\r",
            "dual bytes\r\nip\t\tbytes\r",
            "dual packs\r\nip\t\tpacks\r",
        )
        w = 0.2
        while True:
            try:
                choose = self._q.get(block=True, timeout=w)
            except Empty:
                choose = choose
            finally:

                if choose >= 6:
                    break
                os.system("clear")
                res = self._collect()
                print("==============ip top=============\r")
                print("keys: T/t: tx, R/r: rx, D/d: dual\r")
                print("press q to exit.\r")
                print(titles[choose])
                d_order = self.sort(res[choose])
                for cell in d_order[:10]:
                    print("%s\t%d\r" % (self.toIP(cell[0]), cell[1]))
                w = 3
        self._t.join()

    def toIP(self, v):
        return socket.inet_ntoa(struct.pack('>I', socket.htonl(v)))

    def sort(self, d):
        return sorted(d.items(), key=lambda x: x[1], reverse=True)


if __name__ == "__main__":
    atexit.register(save_old_settings)
    ip = CipTop()
    ip.loop()
    pass
