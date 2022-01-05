# 1、产生背景

​    我们可以采用以下手段来trace内核调用，只说缺点：

## 1.1、kprobe/jprobe/kretprobe

- 侵入式插入ko，危险系数高
- 需要编写内核代码，难度系数大

## 1.2、systemtap

- 需要编写stp代码，步骤较多

## 1.3、bpf（含bcc和libebpf）

- 需要高版本内核支持
- 需要编写两处代码，步骤较多

## 1.4、ftrace-kprobe

- 配置步骤繁琐，从配置到看出效果，至少要经历五个以上的步骤
- 功能受限，对知识点要求较高

## 1.5、perf-tools kprobe

后来我发现了greg 写的一个kprobe 封装工具：https://github.com/brendangregg/perf-tools/blob/master/kernel/kprobe，它可以把繁杂的ftrace 一个 kprobe event 缩略为一个命令，极大拓展了我对ftrace的了解。然而这个工具使用起来仍有以下困难：

- 只能追踪一个kprobe点，我往往需要追踪多个kprobe点；
- 深入追踪困难：比如我们要在__netif_receive_skb_core 函数中打出skb参数中ip头里面的protocol成员，对应的表达式是 **proto=+0x9(+0xf0(%di)):s8**，光推导这个表达式的过程或许要耗费我们10分钟左右的时间。而且这个表达式并非固定不变，在不同的内核上还需要重新计算；

上述两点成为了我使用ftrace的拦路虎，一直想对它改造优化，但受限于自己的蹩脚的bash能力，进展比较慢。于是换了一个思路，改用python。

# 2、surftrace 准备工作

## 2.1、命名约定

在后面的使用中，会用到两类表达式，一种是程序员可以直观通过结构体定义理解的，比如：

```bash
p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)l3%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1
```

称为**结构化表达式**

这类表达式不能被ftrace识别，需要在surftrace中进行转换，转换后的

```bash
p __netif_receive_skb_core proto=+0x9(+0xf0(%di)):x8 ip_src=+0xc(+0xf0(%di)):x32 ip_dst=+0x10(+0xf0(%di)):x32 type=+0x14(+0xf0(%di)):x8 seq=+0x1c(+0xf0(%di)):s16 f:common_pid==0&&proto==1&&ip_src==0x100007f
```

称为**ftrace表达式**

# 2.2、依赖条件

如果你想使用surftrace的完整功能，至少需要以下条件：

- 内核支持ftrace、已经mount了debugfs、root权限
- python2.7或更高，推荐3 以上
下面的条件三选一即可
- 1、公开发行版内核，可以访问 pylcc.openanolis.cn
- 2、公开发行版内核，已经从 http://pylcc.openanolis.cn/db/ 下载了 对应内核的db文件
- 3.1、环境上安装了gdb 版本大于 9，如果是x86 平台，可以直接从 http://pylcc.openanolis.cn/gdb/x64/gdb 下载
- 3.2、安装了对应内核的 vmlinux （结构化表达式依赖，非必须）



## 2.3、参数说明

```bash
usage: surftrace.py [-h] [-v VMLINUX] [-m MODE] [-r RIP] [-f FILE] [-g GDB]
                    [-F FUNC] [-o OUTPUT] [-l LINE] [-a ARCH] [-s] [-S]
                    [traces [traces ...]]

Trace ftrace kprobe events.

positional arguments:
  trace                 set trace args.

optional arguments:
  -h, --help            show this help message and exit
  -v VMLINUX, --vmlinux VMLINUX
                        set vmlinux path.
  -m MODE, --mode MODE  set arg parser, fro
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

```


-f: 从文件中读取表达式，适合大量配置的场景

-o: 将执行过程导出到脚本中

-a:指定cpu架构，涉及到寄存器转换，目前只支持x86_64/aarch64，不指定的话，会根据lscpu获取

-s:打印probe点调用栈，这是个全局开关

-S:只生成ftrace表达式，不下发到ftrace。该模式适合交叉调试场景，比如我们要想在树莓派上去probe 钩子，但是树莓派的资源空间有限，不可能去安装gdb和vmlinux。因此我们可以在宿主机上将结构化表达式转成ftrace表达式。然后在树莓派下发即可。

# 3、实战

我们以open anolis为例，将surftrace.py取下来

```
sudo sh -c su
chmod +x surftrace.py
```

## 3.1、追踪函数入口和返回位置

按Ctrl + C 停止

```bash
#./surftrace.py 'p _do_fork' 'r _do_fork'
echo 'p:f0 _do_fork ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 'r:f1 _do_fork ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f1/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1637241 [000] d... 7462686.335257: f0: (_do_fork+0x0/0x3a0)
 <...>-1637241 [000] d... 7462686.335323: f1: (SyS_clone+0x36/0x40 <- _do_fork)
 systemd-1     [004] d... 7462686.854375: f0: (_do_fork+0x0/0x3a0)
 systemd-1     [004] d... 7462686.854446: f1: (SyS_clone+0x36/0x40 <- _do_fork)
 ……
  systemd-1     [004] d... 7462688.104383: f0: (_do_fork+0x0/0x3a0)
 systemd-1     [004] d... 7462688.104464: f1: (SyS_clone+0x36/0x40 <- _do_fork)
^Cecho 0 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
 <...>-1637241 [000] d... 7462688.134451: f0: (_do_fork+0x0/0x3a0)
 <...>-1637241 [000] d... 7462688.135278: f1: (SyS_clone+0x36/0x40 <- _do_fork)
echo 0 > /sys/kernel/debug/tracing/events/kprobes/f1/enable
 <...>-1637241 [000] d... 7462688.155188: f1: (SyS_clone+0x36/0x40 <- _do_fork)
echo  > /sys/kernel/debug/tracing/kprobe_events
echo 0 > /sys/kernel/debug/tracing/tracing_on
```

可以看到 surftrace支持多个probe，所有表达式要用单引号括起来，表达式中，第一段字母p 表示probe函数入口，r表示probe函数返回位置，第二段为函数符号，该符号必须要在 tracing/available_filter_functions 中可以查找到的

## 3.2、 获取函数入参

还是以_do_fork为例，我们可以查找到它的入参是：

```c
#ifdef CONFIG_FORK2
long _do_fork(struct task_struct *parent,
  		struct task_struct *source,
  		unsigned long clone_flags,
#else
		  long _do_fork(unsigned long clone_flags,
#endif
  	  unsigned long stack_start,
  	  unsigned long stack_size,
  	  int __user *parent_tidptr,
  	  int __user *child_tidptr,
  	  unsigned long tls)
```

我们可以确认它的第一个入参类型是 struct task_struct，如果要获取任务名，即common，可以采用以下方法：

```bash
#./surftrace.py 'p _do_fork comm=%0->comm'
echo 'p:f0 _do_fork comm=+0xafc(%di):string ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1642046 [001] d... 7463503.175187: f0: (_do_fork+0x0/0x3a0) comm="surftrace.py"
 systemd-1     [002] d... 7463503.606161: f0: (_do_fork+0x0/0x3a0) comm="systemd"
 python-16819 [003] d... 7463504.383400: f0: (_do_fork+0x0/0x3a0) comm="python"
 systemd-1     [002] d... 7463504.856166: f0: (_do_fork+0x0/0x3a0) comm="systemd"
 <...>-1642087 [002] d... 7463506.031046: f0: (_do_fork+0x0/0x3a0) comm="sh"
 <...>-1642087 [002] d... 7463506.031363: f0: (_do_fork+0x0/0x3a0) comm="sh"
 systemd-1     [004] d... 7463506.106159: f0: (_do_fork+0x0/0x3a0) comm="systemd"
^Cecho 0 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
 <...>-1642046 [001] d... 7463506.356102: f0: (_do_fork+0x0/0x3a0) comm="surftrace.py"
echo  > /sys/kernel/debug/tracing/kprobe_events
echo 0 > /sys/kernel/debug/tracing/tracing_on
```

参数表达式中，第一个 comm是变量名，可以自己定义，%0 表示第一个入参，%1 表示第二入参，以此类推。~连接符号表示的是后面会紧跟结构化成员，surftrace会根据解析结果得到comm成员类型是string并显示出来。

## 3.3 结构体级联和扩展

仍以 _do_fork 和 struct task_struct为例，在一个结构化表达式中，uesrs=%0**S**~(struct task_struct)->mm->mm_users，入参编号%0与连接符~中间增加了一个S字母来指定整数显示格式，共有SUX三种类型，分别对应有符号十进制、无符号十进制和十六进制。如果不指定，默认是X，16进制

```bash
#级联指针和指定整数数据格式
./surftrace.py 'p _do_fork comm=%0->comm  uesrs=S%0->mm->mm_users'
echo 'p:f0 _do_fork comm=+0xafc(%di):string uesrs=+0x48(+0x858(%di)):s32 ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1650321 [005] d... 7464948.730210: f0: (_do_fork+0x0/0x3a0) comm="surftrace.py" uesrs=1
 systemd-1     [000] d... 7464949.359231: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 <...>-1650361 [005] d... 7464949.424381: f0: (_do_fork+0x0/0x3a0) comm="sh" uesrs=1
 <...>-1650361 [005] d... 7464949.424606: f0: (_do_fork+0x0/0x3a0) comm="sh" uesrs=1
 python-16819 [004] d... 7464950.235552: f0: (_do_fork+0x0/0x3a0) comm="python" uesrs=4
 \....
 #级联结构体成员
 ./surftrace.py 'p _do_fork comm=%0->comm  node=%0->pids[1].node.next'
echo 'p:f0 _do_fork comm=+0xafc(%di):string node=+0x988(%di):x64 ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1652761 [000] d... 7465380.899543: f0: (_do_fork+0x0/0x3a0) comm="surftrace.py" node=0x0
 systemd-1     [000] d... 7465381.610144: f0: (_do_fork+0x0/0x3a0) comm="systemd" node=0x0
 python-16819 [001] d... 7465382.017634: f0: (_do_fork+0x0/0x3a0) comm="python" node=0xffff88062231be08
```

## 3.4 设置过滤器

过滤器需要放在表达式最后，以f:开头，可以使用括号和&& ||逻辑表达式进行组合，具体写法可以参考ftrace文档说明

```bash
./surftrace.py 'p _do_fork comm=%0->comm  uesrs=S%0->mm->mm_users f:comm==systemd'
echo 'p:f0 _do_fork comm=+0xafc(%di):string uesrs=+0x48(+0x858(%di)):s32' >> /sys/kernel/debug/tracing/kprobe_events
echo 'comm==systemd' > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 systemd-1     [002] d... 4817737.060026: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 systemd-1     [002] d... 4817738.310035: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 systemd-1     [002] d... 4817739.560046: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 systemd-1     [001] d... 4817740.607892: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 systemd-1     [001] d... 4817741.810041: f0: (_do_fork+0x0/0x3a0) comm="systemd" uesrs=1
 
 #./surftrace.py 'p _do_fork comm=%0->comm  users=S%0->mm->mm_users f:comm==python||users<4'
echo 'p:f0 _do_fork comm=+0xafc(%di):string users=+0x48(+0x858(%di)):s32 ' >> /sys/kernel/debug/tracing/kprobe_events
echo 'comm==python||users<4' > /sys/kernel/debug/tracing/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1655729 [004] d... 7465872.793430: f0: (_do_fork+0x0/0x3a0) comm="surftrace.py" users=1
 systemd-1     [000] d... 7465872.861176: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
 systemd-1     [000] d... 7465874.111185: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
 <...>-1655773 [003] d... 7465874.123909: f0: (_do_fork+0x0/0x3a0) comm="sh" users=1
 <...>-1655773 [003] d... 7465874.124134: f0: (_do_fork+0x0/0x3a0) comm="sh" users=2
 python-16819 [002] d... 7465874.909735: f0: (_do_fork+0x0/0x3a0) comm="python" users=4
 systemd-1     [000] d... 7465875.361189: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
```

我们还会常用common_pid作为current tid进行过滤，该变量由系统提供，无需定义

```bash
#./surftrace.py 'p _do_fork comm=%0->comm  users=S%0->mm->mm_users f:common_pid==1&&(comm==python||users<4)'
echo 'p:f0 _do_fork comm=+0xafc(%di):string users=+0x48(+0x858(%di)):s32 ' >> /sys/kernel/debug/tracing/kprobe_events
echo 'common_pid==1&&(comm==python||users<4)' > /sys/kernel/debug/tracing/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 systemd-1     [004] d... 7466113.361698: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
 systemd-1     [004] d... 7466114.611729: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
 systemd-1     [004] d... 7466115.861707: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
 systemd-1     [004] d... 7466117.111716: f0: (_do_fork+0x0/0x3a0) comm="systemd" users=1
```

## 3.5 函数内部追踪

以一下汇编代码为例，要获取偏移21位置时的%r12值

```
disas _do_fork
Dump of assembler code for function _do_fork:
   0xffffffff8108a560 <+0>:	callq  0xffffffff8174db10 <__fentry__>
   0xffffffff8108a565 <+5>:	push   %rbp
   0xffffffff8108a566 <+6>:	mov    %rsp,%rbp
   0xffffffff8108a569 <+9>:	push   %r15
   0xffffffff8108a56b <+11>:	push   %r14
   0xffffffff8108a56d <+13>:	push   %r13
   0xffffffff8108a56f <+15>:	push   %r12
   0xffffffff8108a571 <+17>:	xor    %r14d,%r14d
   0xffffffff8108a574 <+20>:	push   %rbx
   0xffffffff8108a575 <+21>:	mov    %rdx,%r12
```

```
#./surftrace.py 'p _do_fork+21 r=%r12'
echo 'p:f0 _do_fork+21 r=%r12 ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1659986 [000] d... 7466637.258116: f0: (_do_fork+0x15/0x3a0) r=0x38
 python-16819 [004] d... 7466637.577201: f0: (_do_fork+0x15/0x3a0) r=0x38
 <...>-497835 [004] d... 7466638.002734: f0: (_do_fork+0x15/0x3a0) r=0x3a
 <...>-497835 [004] d... 7466638.003674: f0: (_do_fork+0x15/0x3a0) r=0x38
```

同样的，也可以对寄存器对应的指针进行解析和过滤，这里就不在详细展开了

## 3.6、函数返回值获取

这个和原kprobe方法一致，返回值用$retval 表示

```
#./surftrace.py 'r _do_fork r=$retval'
echo 'r:f0 _do_fork r=$retval ' >> /sys/kernel/debug/tracing/kprobe_events
echo 1 > /sys/kernel/debug/tracing/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/tracing_on
 <...>-1661938 [000] d... 7466977.685020: f0: (SyS_clone+0x36/0x40 <- _do_fork) r=0x195bfe
 systemd-1     [004] d... 7466977.863627: f0: (SyS_clone+0x36/0x40 <- _do_fork) r=0x195bff
 systemd-1     [004] d... 7466979.113626: f0: (SyS_clone+0x36/0x40 <- _do_fork) r=0x195c00
 <...>-497835 [000] d... 7466979.731526: f0: (sys_vfork+0x3c/0x40 <- _do_fork) r=0x195c01
```

## 3.7、skb解析处理

sk_buff 是linux网络协议栈重要的结构体，但是通过上面的方法，并不能直接解析到我们关注的报文内容，需要进行特殊处理。以追踪icmp接收ping报文为例，我们在__netif_receive_skb_core 函数中进行probe和过滤

```bash
#./surftrace.py 'p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=X@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1'
echo 'p:f0 __netif_receive_skb_core proto=+0x9(+0xf0(%di)):u8 ip_src=+0xc(+0xf0(%di)):u32 ip_dst=+0x10(+0xf0(%di)):u32 data=+0x16(+0xf0(%di)):x16' >> /sys/kernel/debug/tracing/kprobe_events
echo 'proto==1&&ip_src==0x100007f' > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/kprobes/f0/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <...>-2076163 [000] d.s1 4818041.743856: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x4dec
 <...>-2076163 [000] d.s1 4818041.743905: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x4df4
 <...>-2076163 [000] d.s1 4818042.767865: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0xef26
 <...>-2076163 [000] d.s1 4818042.767914: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0xef2e
 <...>-2076163 [000] d.s1 4818043.791858: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x9069
 <...>-2076163 [000] d.s1 4818043.791905: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x9071
 <...>-2076163 [000] d.s1 4818044.815861: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x31a6
 <...>-2076163 [000] d.s1 4818044.815911: f0: (__netif_receive_skb_core+0x0/0xa80) proto=1 ip_src=127.0.0.1 ip_dst=127.0.0.1 data=0x31ae
```

协议的获取表达式为 @(struct iphdr *)l3%0->protocol，和之前不一样的是，寄存器的结构体名左括号加了@符号进行特殊标记，表示需要用该结构体来解析skb->data指针数据，结构体名和右括号后加了l3标记（命名为右标记），表示当前skb->data指向了TCP/IP 层3位置。

右标记有l2、l3、l4三个选项，也可以不标记，默认为l3，如 ip_src=@(struct iphdr *)%0->saddr，没有右标记。

报文结构体有 'struct ethhdr', 'struct iphdr', 'struct icmphdr', 'struct tcphdr', 'struct udphdr'五类，如果协议栈层级和报文结构体对应不上，解析器会报参数错误，如右标记为l3，但是报文结构体是 struct ethhdr类型；

'struct icmphdr', 'struct tcphdr', 'struct udphdr'这三个4层结构体增加了xdata成员，用于获取协议对应报文内容。xdata有 cdata. sdata, ldata, qdata 四类场景，位宽对应 1 2 4 8. 数组下标是按照位宽进行对齐的，如实例表达式中的 data=%0~$(struct icmphdr)l3->sdata[1],sdata[1]表示要提取icmp报文中的2~3字节内容

surftrace 会对以 ip_xx开头的变量进行ipv4<->u32 ，如 ip_src=@(struct iphdr *)%0->saddr，会转成对应的IP格式。对B16\_、B32\_、B64\_、b16\_、b32\_、b64\_开头的变量也会进行大小端转换，B开头按照16进制输出，b以10进制输出。

## 3.8 event 事件处理
trace event 信息参考 /sys/kernel/debug/tracing/events目录下的事件 描述，以追踪wakeup等待超过10ms任务为例，
```bash
#./surftrace.py 'e sched/sched_stat_wait f:delay>1000000'
echo 'delay>1000000' > /sys/kernel/debug/tracing/instances/surftrace/events/sched/sched_stat_wait/filter
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/events/sched/sched_stat_wait/enable
echo 0 > /sys/kernel/debug/tracing/instances/surftrace/options/stacktrace
echo 1 > /sys/kernel/debug/tracing/instances/surftrace/tracing_on
 <idle>-0     [001] dN.. 11868700.419049: sched_stat_wait: comm=h2o pid=3046552 delay=87023763 [ns]
 <idle>-0     [005] dN.. 11868700.419049: sched_stat_wait: comm=h2o pid=3046617 delay=87360020 [ns]

```