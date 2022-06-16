# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     attach.py
   Description :
   Author :       liaozhaoyan
   date：          2022/6/15
-------------------------------------------------
   Change Activity:
                   2022/6/15:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

SEC("kprobe/finish_task_switch")
int j_wake_up_new_task2(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);

    bpf_printk("hello lcc2, parent: %d\n", _(parent->tgid));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class Cattach(ClbcBase):
    def __init__(self):
        super(Cattach, self).__init__("attach", bpf_str=bpfPog, attach=0)
        self.attachKprobe("j_wake_up_new_task2", "wake_up_new_task")
        while True:
            time.sleep(1)


if __name__ == "__main__":
    attach = Cattach()
    pass

