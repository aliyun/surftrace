#ifndef PROC_DEF_H
#define PROC_DEF_H
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#define DEFINE_PROC_ATTRIBUTE(name, __write)				\
	static int name##_open(struct inode *inode, struct file *file)	\
	{								\
		return single_open(file, name##_show, PDE_DATA(inode));	\
	}								\
									\
	static const struct file_operations name##_fops = {		\
		.owner		= THIS_MODULE,				\
		.open		= name##_open,				\
		.read		= seq_read,				\
		.write		= __write,				\
		.llseek		= seq_lseek,				\
		.release	= single_release,			\
	}

#define DEFINE_PROC_ATTRIBUTE_RW(name)					\
	static ssize_t name##_write(struct file *file,			\
				    const char __user *buf,		\
				    size_t count, loff_t *ppos)		\
	{								\
		return name##_store(PDE_DATA(file_inode(file)), buf,	\
				    count);				\
	}								\
	DEFINE_PROC_ATTRIBUTE(name, name##_write)

#define DEFINE_PROC_ATTRIBUTE_RO(name)	\
	DEFINE_PROC_ATTRIBUTE(name, NULL)

#endif