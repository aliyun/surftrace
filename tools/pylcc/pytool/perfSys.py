# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     perfSys
   Description :
   Author :       liaozhaoyan
   date：          2022/10/19
-------------------------------------------------
   Change Activity:
                   2022/10/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
import argparse
import psutil
from datetime import datetime
from multiprocessing import cpu_count
from treelib import Tree
from surftrace.surfElf import CelfKsym
from pylcc.lbcBase import ClbcBase
from pylcc.perfEvent import *
from pylcc.lbcStack import getKStacks
from quickSvg import Flame

bpfPog = r"""
#include "lbc.h"

#define STACK_COUNT 4096
LBC_HASH(calls, u32, u64, STACK_COUNT);
LBC_STACK(call_stack, STACK_COUNT);

static inline void add_hash(struct bpf_map_def* maps, u32 k, u64 v) {
    u64 *pv = bpf_map_lookup_elem(maps, &k);
    if (pv) {
        __sync_fetch_and_add(pv, v);
    }
    else {
        bpf_map_update_elem(maps, &k, &v, BPF_NOEXIST);
    }
}

#define incr_hash(maps, k) add_hash(maps, k, 1)

SEC("perf_event")
int trace_stack(struct bpf_perf_event_data *ctx) {
    int id = bpf_get_stackid(ctx, &call_stack, KERN_STACKID_FLAGS);
    if (id > 0) {
        incr_hash(&calls, id);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


def getValue(data):
    return data['count']


def getNote(tree, node):
    root = tree.get_node(tree.root)
    perRoot = node.data['count'] * 100.0 / root.data['count']

    parent = tree.parent(node.identifier)
    if parent is None:
        perParent = 100.0
    else:
        perParent = node.data['count'] * 100.0 / parent.data['count']
    return "catch %d samples, %f%% from root, %f%% from parent" % (node.data['count'], perRoot, perParent)


class CperfSys(ClbcBase):
    def __init__(self, freq=200, wait=2, cpus=None):
        super(CperfSys, self).__init__("sysHigh", bpf_str=bpfPog)
        self._freq = freq
        self._wait = wait
        self._cpus = cpus
        self._ksym = CelfKsym()

    def loop(self):
        pfConfig = {
            "sample_freq": self._freq,
            "freq": 1,
            "type": PerfType.SOFTWARE,
            "config": PerfSwIds.CPU_CLOCK,
        }
        if self._cpus is None:
            self.attachAllCpuPerf("trace_stack", pfConfig)
        else:
            for index, isOn in enumerate(self._cpus):
                if isOn:
                    self.attachPerfEvent("trace_stack", pfConfig, pid=-1, cpu=index)
        time.sleep(self._wait)
        res = self.maps['calls'].get()
        self.setupTree(res)

    def _filterChild(self, tree, nid, tag):
        for child in tree.children(nid):
            if child.tag == tag:
                return child
        return None

    def _setupTitle(self):
        onCpu = []
        for index, isOn in enumerate(self._cpus):
            if isOn:
                onCpu.append(str(index))
        return "sysHigh for cpu " + ":".join(onCpu)

    def setupTree(self, res):
        tree = Tree()
        root = tree.create_node(tag="total", parent=tree.root, data={"func": "total", "count": 0})
        for k, v in res.items():
            last = root
            syms = getKStacks(self.maps['call_stack'], k, self._ksym)
            for sym in syms[::-1]:
                sym = sym.encode()
                node = self._filterChild(tree, last.identifier, sym)
                if node is None:
                    node = tree.create_node(tag=sym, parent=last, data={"func": sym, "count": v})
                else:
                    node.data["count"] += v
                last = node
            root.data['count'] += v
        flame = Flame("%s.svg" % datetime.now().strftime("%Y%m%d_%H%M%S"))
        flame.render(tree, getValue, getNote, self._setupTitle())


class CperfLoop(object):
    def __init__(self, args):
        super(CperfLoop, self).__init__()
        self._args = args
        self._cpus = cpu_count()

    def _check(self, last, now):
        perSys = []
        for i in range(self._cpus):
            perSys.append(now[i].system - last[i].system)

        isRun = False
        cpus = []
        for v in perSys:
            per = v / self._args.interval * 100.0
            if per >= self._args.gate:
                cpus.append(1)
                isRun = True
            else:
                cpus.append(0)
        print(perSys, isRun)
        if isRun:
            bpf = CperfSys(freq=self._args.freq, wait=self._args.sample, cpus=cpus)
            bpf.loop()

    def loop(self):
        while True:
            last = psutil.cpu_times(percpu=True)
            time.sleep(self._args.interval)
            now = psutil.cpu_times(percpu=True)
            self._check(last, now)


if __name__ == "__main__":
    examples = """examples: python perfSys -g 10 -i 3 -s 3 -f 200"""

    parser = argparse.ArgumentParser(
        description="collect sys high flame svg.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )
    parser.add_argument('-i', '--interval', type=float, dest='interval', default=3,
                        help='system usage sampling interval time, uint second.')
    parser.add_argument('-g', '--gate', type=float, dest='gate', default=10,
                        help='system usage limit trigger svg.')
    parser.add_argument('-s', '--sample', type=float, dest='sample', default=3,
                        help='perf sample time.')
    parser.add_argument('-f', '--freq', type=int, dest='freq', default=200,
                        help='perf sample frequency.')
    args = parser.parse_args()
    loop = CperfLoop(args)
    loop.loop()
    pass
