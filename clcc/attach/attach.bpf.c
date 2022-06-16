#include "lbc.h"

SEC("kprobe/finish_task_switch")
int j_wake_up_new_task2(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);

    bpf_printk("hello lcc2, parent: %d\n", _(parent->tgid));
    return 0;
}

char _license[] SEC("license") = "GPL";
