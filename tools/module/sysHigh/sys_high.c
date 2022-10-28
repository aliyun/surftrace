#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "proc_def.h"

#define PROC_PATH "coolbpf"

static int sys_high_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "%llu\n", 0ULL);
	return 0;
}

static ssize_t __attribute__((optimize("O0"))) sys_high_store(void *priv, const char __user *buf, size_t count)
{
	u64 val;
	u64 i, j;

	if (kstrtou64_from_user(buf, count, 0, &val))
		return -EINVAL;

	for (i = 0; i < val; i ++)
	    for (j = 0; j < val; j ++);
	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(sys_high);

static u64* sys_fly_var = NULL;
static int sys_fly_show(struct seq_file *m, void *ptr)
{
	seq_printf(m, "0x%llx: %llu\n", (u64)sys_fly_var, *sys_fly_var);
	return 0;
}

static ssize_t sys_fly_store(void *priv, const char __user *buf, size_t count)
{
	if (kstrtou64_from_user(buf, count, 0, sys_fly_var))
		return -EINVAL;

	return count;
}
DEFINE_PROC_ATTRIBUTE_RW(sys_fly);

static int __init sys_high_init(void)
{
	int ret;
	struct proc_dir_entry *root_dir = NULL;

	root_dir = proc_mkdir(PROC_PATH, NULL);
	if (!root_dir) {
		ret = -ENOMEM;
	}

	if (!proc_create("sys_high", S_IRUSR | S_IWUSR, root_dir,
			 &sys_high_fops)){
		ret = -ENOMEM;
		goto remove_proc;
	}

	sys_fly_var = (u64*)kmalloc(sizeof(u64), GFP_KERNEL);
	*sys_fly_var = 0ULL;
	if (sys_fly_var == NULL) {
	    ret = -ENOMEM;
		goto remove_proc;
	}
	if (!proc_create("sys_fly", S_IRUSR | S_IWUSR, root_dir,
			 &sys_fly_fops)){
		ret = -ENOMEM;
		goto free_var;
	}
	return 0;

free_var:
    kfree(sys_fly_var);
remove_proc:
	remove_proc_subtree(PROC_PATH, NULL);
	return -ret;
}

static void __exit sys_high_exit(void)
{
    kfree(sys_fly_var);
	remove_proc_subtree(PROC_PATH, NULL);
}

module_init(sys_high_init);
module_exit(sys_high_exit);
MODULE_LICENSE("GPL");
