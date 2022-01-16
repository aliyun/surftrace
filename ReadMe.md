# 1、简介

​	surftrace是在ftrace基础上封装的一系列工具集，用于trace内核信息，当前发行版主要包含 surftrace、surfGuide两大个工具，后期还将包含pylcc(python libbpf compile collections)。

![image-20220116004341741](ReadMe.assets/image-20220116004341741.png)

## 1.1、ftrace原理与不足

​	ftrace是一个内核中的追踪器，用于帮助系统开发者或设计者查看内核运行情况，它可以被用来调试或者分析延迟/性能等常见问题。早期 ftrace 是一个 function tracer，仅能够记录内核的函数调用流程。如今ftrace已经成为一个开发框架，从2.6内核开始引入，是一套公认安全、可靠、高效的内核数据获取方式。

​    ftrace对使用者的要求比较高，以对内核符号 wake_up_new_task 进行trace，同时要获取入参(struct task_struct *)->comm 成员信息为例，启动配置需要经历三个步骤：

```bash
echo 'p:f0 wake_up_new_task comm=+0x678(%di):string' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
```

​	要想停止需要继续配置如下：

```bash
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo -:f0 >> /sys/kernel/debug/tracing/kprobe_events
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
```

​	一共需要六个步骤。其中，最困难的是第一个参数解析步骤。通常情况下，需要使用gdb 加载对应内核vmlinux， 对 struct task_struct 结构体中 comm成员进行偏移计算。上述方法如果不经常使用，重新手工操作的时间成本非常高，导致真正直接采用ftrace对内核信息进行采集的案例非常少，相关资料文献也匮乏。

## 1.2、surftrace目标

​	surftrace的主要目标是为了降低ftrace，达到快速高效获取内核信息目标。综合来说要达到以下效果：

1. 一键trace内核符号，并获取指定内核数据；
2. 除了C和linux 操作系统内核，用户无需新增学习掌握其它知识点（需要获取数据进行二次处理除外）；
3. 覆盖大部分主流发行版内核；

# 2、surftrace 命令使用

​	使用surftrace，需要满足以下条件：

1. 公开发行版linux内核，支持目录参考：http://pylcc.openanolis.cn/version/  （持续更新）
2. 内核支持ftrace，已配置了debugfs，root权限；
3. Python2 >= 2.7; Python3 >= 3.5，已安装pip；

​	surftrace支持 remote（默认），local和gdb三种表达式解析器，要求分别如下：

1. remote mode：可以访问pylcc.openanolis.cn
2. local mode：从http://pylcc.openanolis.cn/db/ 下载对应arch和内核的下载到本地
3. gdb mode：gdb version > 8.0，存放有对应内核的vmlinux；对于gdb模式而言，不受公开发行版内核限制

## 2.1、安装

​	我们以龙蜥 4.19.91-24.8.an8.x86_64内核为例，需要root用户，执行以下命令进行安装：

```
pip3 install surftrace
Collecting surftrace
  Downloading http://mirrors.cloud.aliyuncs.com/pypi/packages/b9/a2/f7e04bb8ebb12e6517162a70886e3ffe8d466437b15624590c9301fdcc52/surftrace-0.2.tar.gz
Building wheels for collected packages: surftrace
  Running setup.py bdist_wheel for surftrace ... done
  Stored in directory: /root/.cache/pip/wheels/cf/28/93/187f359be189bf0bf4a70197c53519c6ca54ffb957bcbebf5a
Successfully built surftrace
Installing collected packages: surftrace
Successfully installed surftrace-0.2
```

​	检查安装是否成功

```
surftrace --help
usage: surftrace [-h] [-v VMLINUX] [-m MODE] [-d DB] [-r RIP] [-f FILE]
                 [-g GDB] [-F FUNC] [-o OUTPUT] [-l LINE] [-a ARCH] [-s] [-S]
                 [traces [traces ...]]

Trace ftrace kprobe events.

positional arguments:
  traces                set trace args.

optional arguments:
  -h, --help            show this help message and exit
  -v VMLINUX, --vmlinux VMLINUX
                        set vmlinux path.
  -m MODE, --mode MODE  set arg parser, fro
  -d DB, --db DB        set local db path.
  -r RIP, --rip RIP     set remote server ip, remote mode only.
  -f FILE, --file FILE  set input args path.
  -g GDB, --gdb GDB     set gdb exe file path.
  -F FUNC, --func FUNC  disasassemble function.
  -o OUTPUT, --output OUTPUT
                        set output bash file
  -l LINE, --line LINE  get file disasemble info
  -a ARCH, --arch ARCH  set architecture.
  -s, --stack           show call stacks.
  -S, --show            only show expressions.

examples:
```

## 2.2、常规函数入口trace

​	接下来我们以 以下两个常用内核符号为例，它的原型定义如下：

```c
void wake_up_new_task(struct task_struct *p);
struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op);
```

### 2.2.1、追踪符号入口和返回点

​	命令：surftrace 'p wake_up_new_task' 'r wake_up_new_task'

```bash
surftrace 'p wake_up_new_task' 'r wake_up_new_task'
echo 'p:f0 wake_up_new_task' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 'r:f1 wake_up_new_task' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f1/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2336  [001] ....  1447.877666: f0: (wake_up_new_task+0x0/0x280)
 surftrace-2336  [001] d...  1447.877670: f1: (_do_fork+0x153/0x3d0 <- wake_up_new_task)
```

​	示例中入参有两个表达式，所有表达式要用单引号括起来。

- 'p wake_up_new_task'：p表示表示probe函数入口；
- 'r wake_up_new_task'：r表示probe函数返回位置；

​	后面的wake_up_new_task是要trace的函数符号，这个符号必须要在tracing/available_filter_functions 中可以找到的。

### 2.2.2、获取函数入参

​	要获取 do_filp_open 函数 第一个入参dfd，它的数据类型是：int。

​	命令：surftrace 'p do_filp_open dfd=%0'

```bash
surftrace 'p do_filp_open dfd=%0'
echo 'p:f0 do_filp_open dfd=%di:u32' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2435  [001] ....  2717.606277: f0: (do_filp_open+0x0/0x100) dfd=4294967196
 AliYunDun-1812  [000] ....  2717.655955: f0: (do_filp_open+0x0/0x100) dfd=4294967196
 AliYunDun-1812  [000] ....  2717.856227: f0: (do_filp_open+0x0/0x100) dfd=4294967196
```

- dfd是自定义变量，可以自行定义，名字不冲突即可
- %0表示第一个入参，%1表示第二个……



​	前面打印中，dfd是按照十进制显示的，可能没有十六进制那么直观，指定十六进制的方法：

​	命令：surftrace 'p do_filp_open dfd=X%0'

```
surftrace 'p do_filp_open dfd=X%0'
echo 'p:f0 do_filp_open dfd=%di:x32' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2459  [000] ....  3137.167885: f0: (do_filp_open+0x0/0x100) dfd=0xffffff9c
 AliYunDun-1812  [001] ....  3137.171997: f0: (do_filp_open+0x0/0x100) dfd=0xffffff9c
 AliYunDun-1826  [001] ....  3137.201401: f0: (do_filp_open+0x0/0x100) dfd=0xffffff9c
```

​	传参编号%前面使用了X进制类型标识符，共有SUX三种类型，分别对应有符号十进制、无符号十进制和十六进制，不指定默认为U类型。

### 2.2.3、解析入参结构体

​	wake_up_new_task入参类型为struct task_struct *，如果要获取入参中comm成员，即任务名，

​	命令：surftrace 'p wake_up_new_task comm=%0->comm'

```bash
surftrace 'p wake_up_new_task comm=%0->comm'
echo 'p:f0 wake_up_new_task comm=+0xae0(%di):string' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2421  [000] ....  2368.261019: f0: (wake_up_new_task+0x0/0x280) comm="surftrace"
 bash-2392  [001] ....  2375.809655: f0: (wake_up_new_task+0x0/0x280) comm="bash"
 bash-2392  [001] ....  2379.038534: f0: (wake_up_new_task+0x0/0x280) comm="bash"
 bash-2392  [000] ....  2381.237443: f0: (wake_up_new_task+0x0/0x280) comm="bash"
```

​	方法和C语言获取结构体成员方法一样。

​	结构体类型可以级联访问：

```bash
 surftrace 'p wake_up_new_task uesrs=S%0->mm->mm_users'
echo 'p:f0 wake_up_new_task uesrs=+0x58(+0x850(%di)):s32' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2471  [001] ....  3965.234680: f0: (wake_up_new_task+0x0/0x280) uesrs=2
 bash-2392  [000] ....  3970.094475: f0: (wake_up_new_task+0x0/0x280) uesrs=1
 bash-2392  [000] ....  3971.954463: f0: (wake_up_new_task+0x0/0x280) uesrs=1
```

```bash
surftrace 'p wake_up_new_task node=%0->se.run_node.rb_left'
echo 'p:f0 wake_up_new_task node=+0xa8(%di):u64' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 surftrace-2543  [001] ....  5926.605145: f0: (wake_up_new_task+0x0/0x280) node=0
 bash-2392  [001] ....  5940.292293: f0: (wake_up_new_task+0x0/0x280) node=0
 bash-2392  [001] ....  5945.207106: f0: (wake_up_new_task+0x0/0x280) node=0
 systemd-journal-553   [000] ....  5953.211998: f0: (wake_up_new_task+0x0/0x280) node=0
```

### 2.2.4、设置过过滤器

​	过滤器需要放在表达式最后，以f:开头，可以使用括号和&& ||逻辑表达式进行组合，具体写法可以参考ftrace文档说明

​	命令行 surftrace 'p wake_up_new_task comm=%0->comm f:comm=="python3"'

```bash
surftrace 'p wake_up_new_task comm=%0->comm f:comm=="python3"'
echo 'p:f0 wake_up_new_task comm=+0xb28(%di):string' >> /sys/kernel/debug/tracing/kprobe_events
echo 'comm=="python3"' > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-2640781 [002] .... 6305734.444913: f0: (wake_up_new_task+0x0/0x250) comm="python3"
 <...>-2640781 [002] .... 6305734.447806: f0: (wake_up_new_task+0x0/0x250) comm="python3"
 <...>-2640781 [002] .... 6305734.450897: f0: (wake_up_new_task+0x0/0x250) comm="python3"
```

​	系统会默认提供 'common_pid', 'common_preempt_count', 'common_flags', 'common_type' 这5个变量作为过滤器，该变量由系统提供，无需额外定义。

### 2.2.5、函数内部追踪

​	函数内部追踪需要结合函数内部汇编代码进行推导，该方法并不通用，该内容操作进供参考。反汇编do_filp_open函数

```asm
3699	in fs/namei.c
   0xffffffff812adb65 <+85>:	mov    %r13d,%edx
   0xffffffff812adb70 <+96>:	or     $0x40,%edx
   0xffffffff812adb73 <+99>:	mov    %r12,%rsi
   0xffffffff812adb76 <+102>:	mov    %rsp,%rdi
   0xffffffff812adb89 <+121>:	callq  0xffffffff812ac760 <path_openat>
   0xffffffff812adb92 <+130>:	mov    %rax,%rbx

3700	in fs/namei.c
   0xffffffff812adb8e <+126>:	cmp    $0xfffffffffffffff6,%rax
   0xffffffff812adb95 <+133>:	je     0xffffffff812adbb4 <do_filp_open+164>

3701	in fs/namei.c
   0xffffffff812adbb4 <+164>:	mov    %r13d,%edx
   0xffffffff812adbb7 <+167>:	mov    %r12,%rsi
   0xffffffff812adbba <+170>:	mov    %rsp,%rdi
   0xffffffff812adbbd <+173>:	callq  0xffffffff812ac760 <path_openat>
   0xffffffff812adbc2 <+178>:	mov    %rax,%rbx
   0xffffffff812adbc5 <+181>:	jmp    0xffffffff812adb97 <do_filp_open+135>

3702	in fs/namei.c
   0xffffffff812adb97 <+135>:	cmp    $0xffffffffffffff8c,%rbx
   0xffffffff812adb9b <+139>:	je     0xffffffff812adbc7 <do_filp_open+183>
```

对应源码

```c
struct file *do_filp_open(int dfd, struct filename *pathname,
  		const struct open_flags *op)
{
  	struct nameidata nd;
  	int flags = op->lookup_flags;
  	struct file *filp;
  
  	set_nameidata(&nd, dfd, pathname);
  	filp = path_openat(&nd, op, flags | LOOKUP_RCU);
  	if (unlikely(filp == ERR_PTR(-ECHILD)))
  		filp = path_openat(&nd, op, flags);
  	if (unlikely(filp == ERR_PTR(-ESTALE)))
  		filp = path_openat(&nd, op, flags | LOOKUP_REVAL);
  	restore_nameidata();
  	return filp;
}
```

要获取 3699行 filp = path_openat(&nd, op, flags | LOOKUP_RCU) 对应的filp的值

```bash
surftrace 'p do_filp_open+121 filp=X!(u64)%ax'
echo 'p:f0 do_filp_open+121 filp=%ax:x64' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-1315799 [006] d.Z. 6314249.201847: f0: (do_filp_open+0x79/0xd0) filp=0xffff929db2819840
 <...>-4006158 [014] d.Z. 6314249.326736: f0: (do_filp_open+0x79/0xd0) filp=0xffff929daeac48c0
```

变量表达式：filp=X!(u64)%ax 中，使用!对寄存器类型进行数据类型强制转换，括号当中的是是数据类型定义。

展开 struct file 结构体定义：

```c
struct file {
    union {
        struct llist_node fu_llist;
        struct callback_head fu_rcuhead;
    } f_u;
    struct path f_path;
    struct inode *f_inode;
    const struct file_operations *f_op;
    spinlock_t f_lock;
    enum rw_hint f_write_hint;
    atomic_long_t f_count;
    unsigned int f_flags;
    fmode_t f_mode;
    struct mutex f_pos_lock;
    loff_t f_pos;
    struct fown_struct f_owner;
    const struct cred *f_cred;
    struct file_ra_state f_ra;
    u64 f_version;
    void *f_security;
    void *private_data;
    struct list_head f_ep_links;
    struct list_head f_tfile_llink;
    struct address_space *f_mapping;
    errseq_t f_wb_err;
}
```

​	如果要获取此时的f_pos值，可以这样获取

​	命令行：surftrace 'p do_filp_open+121 pos=X!(struct file*)%ax->f_pos'

```bash
surftrace 'p do_filp_open+121 pos=X!(struct file*)%ax->f_pos'
echo 'p:f0 do_filp_open+121 pos=+0x68(%ax):x64' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-1334277 [010] d.Z. 6314645.646230: f0: (do_filp_open+0x79/0xd0) pos=0x0
 <...>-2916553 [002] d.Z. 6314645.653164: f0: (do_filp_open+0x79/0xd0) pos=0x0
 <...>-2916553 [002] d.Z. 6314645.653253: f0: (do_filp_open+0x79/0xd0) pos=0x0
```

获取方法和前面保持一致。

## 2.3、获取返回值

​	前文已经描述采用r 对事件类型进行标识，返回寄存器统一用$retval标识，与ftrace保持一致，以获取do_filp_open函数返回值为例：

​	命令行：surftrace 'r do_filp_open filp=$retval'

```bash
surftrace 'r do_filp_open filp=$retval'
echo 'r:f0 do_filp_open filp=$retval:u64' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-1362926 [010] d... 6315264.198718: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) filp=18446623804769722880
 <...>-4006154 [008] d... 6315264.256749: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) filp=18446623804770426624
 <...>-4006154 [008] d... 6315264.256776: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) filp=18446623804770425344
```

​	获取 struct file 中f_pos成员

​	命令行：surftrace 'r do_filp_open pos=$retval->f_pos'

```bash
surftrace 'r do_filp_open pos=$retval->f_pos'
echo 'r:f0 do_filp_open pos=+0x68($retval):u64' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-1371049 [008] d... 6315439.568814: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) pos=0
 systemd-journal-3665  [012] d... 6315439.568962: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) pos=0
 systemd-journal-3665  [012] d... 6315439.571519: f0: (do_sys_openat2+0x1b6/0x260 <- do_filp_open) pos=0
```

## 2.4、skb处理

​	sk_buff 是linux网络协议栈重要的结构体，通过前面的方法，并不能直接解析到我们关注的报文内容，需要进行特殊处理。以追踪icmp接收ping报文为例，我们在__netif_receive_skb_core 函数中进行probe和过滤:

​	命令行 surftrace 'p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=X@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1'

​	同时可能需要 执行 ping127.0.0.1

```bash
surftrace 'p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=X@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1'
echo 'p:f0 __netif_receive_skb_core proto=+0x9(+0xe8(%di)):u8 ip_src=+0xc(+0xe8(%di)):u32 ip_dst=+0x10(+0xe8(%di)):u32 data=+0x16(+0xe8(%di)):x16' >> /sys/kernel/debug/tracing/kprobe_events
echo 'proto==1&&ip_src==0x100007f' > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-1420827 [013] ..s1 6316511.011244: f0: (__netif_receive_skb_core+0x0/0xc10) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x4a0d
 <...>-1420827 [013] ..s1 6316511.011264: f0: (__netif_receive_skb_core+0x0/0xc10) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x4a15
```

​	协议的获取表达式为 @(struct iphdr *)l3%0->protocol，和之前不一样的是，寄存器的结构体名左括号加了@符号进行特殊标记，表示需要用该结构体来解析skb->data指针数据，结构体名和右括号后加了l3标记（命名为右标记），表示当前skb->data指向了TCP/IP 层3位置。

- 右标记有l2、l3、l4三个选项，也可以不标记，默认为l3，如 ip_src=@(struct iphdr *)%0->saddr，没有右标记。
- 报文结构体有 'struct ethhdr', 'struct iphdr', 'struct icmphdr', 'struct tcphdr', 'struct udphdr'五类，如果协议栈层级和报文结构体对应不上，解析器会报参数错误，如右标记为l3，但是报文结构体是 struct ethhdr类型；
- 'struct icmphdr', 'struct tcphdr', 'struct udphdr'这三个4层结构体增加了xdata成员，用于获取协议对应报文内容。xdata有 cdata. sdata, ldata, qdata, Sdata 五种类型，位宽对应 1 2 4 8 和字符串. 数组下标是按照位宽进行对齐的，如实例表达式中的 data=%0~$(struct icmphdr)l3->sdata[1],sdata[1]表示要提取icmp报文中的2~3字节内容
- surftrace 会对以 ip_xx开头的变量进行ipv4<->u32 ，如 ip_src=@(struct iphdr *)%0->saddr，会转成对应的IP格式。对B16_、B32_、B64_、b16_、b32_、b64_开头的变量也会进行大小端转换，B开头按照16进制输出，b以10进制输出。

## 2.5、event

​	trace event 信息参考 /sys/kernel/debug/tracing/events目录下的事件 描述，以追踪wakeup等待超过10ms任务为例

​	命令行 surftrace 'e sched/sched_stat_wait f:delay>1000000'

```bash
surftrace 'e sched/sched_stat_wait f:delay>1000000'
echo 'delay>1000000' > /sys/kernel/debug/tracing/instances/surftrace/events/sched/sched_stat_wait/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/sched/sched_stat_wait/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
<idle>-0     [001] dN.. 11868700.419049: sched_stat_wait: comm=h2o pid=3046552 delay=87023763 [ns]
 <idle>-0     [005] dN.. 11868700.419049: sched_stat_wait: comm=h2o pid=3046617 delay=87360020 [ns]
```



# 3、surfGuide 使用

​	surfGuide可以直接运行，命令行已经有一些使用帮助提示。现在手头任务紧张，等有空了再补充完善吧。

​	安装：pip install surfGuide

​	然后运行 surfGuide 就可以使用了。

# 4、使用surfGuide发布通用命令

同上

# 5、接管surftrace数据进行开发处理

同上上