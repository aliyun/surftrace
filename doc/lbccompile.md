# 1、coolbpf compile server镜像说明
![](image)
&emsp; coolbpf compile server镜像可以提供以下服务:

* bpf.c 文件编译服务
* btf文件在线获取服务

&emsp;要运行coolbpf server镜像，需要以下准备工作：

1. 目标实例安装docker或者其它容器服务
2. 目标实例预留100G左右的磁盘空间（存放btf/header/db文件）
3. 如果要实时更新btf/header/db，需要支持访问www.foxbeaver.cn
4. surftrace >=0.7.0 pylcc >= 0.2.10
5. 默认绑定7655 tcp 端口

# 2、搭建coolbpf 编译服务
&emsp;我们以在192.168.22.4 实例上搭建coolbpf compile server服务上搭建服务为例。
## 2.1、同步db/btf：
&emsp;在实例上创建目录，如/root/1ext/hive，并在该目录下，同步db/btf/header数据源：

```bash
rsync -av www.foxbeaver.cn::pylcc/btf .
rsync -av www.foxbeaver.cn::pylcc/db .
rsync -av www.foxbeaver.cn::pylcc/header .
```
&emsp;建议将rsync 放到crontab 定时任务中去，与远端数据源定期保持同步。
## 2.2、启动容器

```bash
docker run  --entrypoint="/bin/bash" --name surfd  -v /root/1ext/hive:/home/hive -p 7655:7655 -itd registry.cn-hangzhou.aliyuncs.com/sysom/coolbpf:v1.14 /home/lbc/run.sh 127.0.0.1
```

## 2.3、验证

hello.py 代码

```python
import time
from pylcc.lbcBase import ClbcBase

bpfPog = r"""
#include "lbc.h"

SEC("kprobe/wake_up_new_task")
int j_wake_up_new_task(struct pt_regs *ctx)
{
    struct task_struct* parent = (struct task_struct *)PT_REGS_PARM1(ctx);
    bpf_printk("hello lcc, parent: %d\n", _(parent->tgid));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""

class Chello(ClbcBase):
    def __init__(self):
        super(Chello, self).__init__("hello", bpf_str=bpfPog)
        while True:
            time.sleep(1)


if __name__ == "__main__":
    hello = Chello()
    pass
```

执行：

```
#python hello.py
remote server compile success.
^CTraceback (most recent call last):
  File "hello.py", line 26, in <module>
    hello = Chello()
  File "hello.py", line 22, in __init__
    time.sleep(1)
KeyboardInterrupt

[root@localhost.localdomain /root/1ext/hive]
#cat /sys/kernel/debug/tracing/trace_pipe
         python3-1770  [000] .... 2073737.147865: 0: hello lcc, parent: 40096
           <...>-40096 [003] .... 2073737.163631: 0: hello lcc, parent: 40097
           <...>-40096 [003] .... 2073737.166262: 0: hello lcc, parent: 40096
           <...>-40096 [003] .... 2073737.166328: 0: hello lcc, parent: 40096
           <...>-40096 [003] .... 2073737.166376: 0: hello lcc, parent: 40096
           <...>-40096 [003] .... 2073737.166437: 0: hello lcc, parent: 40096
```
