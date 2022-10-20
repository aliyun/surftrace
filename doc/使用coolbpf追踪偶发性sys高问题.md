
# 1、背景
&emsp;linux sys高意味着cpu消耗在内核态，可能会引起正常的业务抖动，通常采用perf 抓热点的方法进行跟踪定位。但是如果sys高毫无规律并且时间较为短暂，往往来不及执行采样现象已经消失，或采用基数太大，无法准确分析出热点，导致采用perf往往无法有效跟踪此类问题。
&emsp;coolbpf可以友好地支持perf事件，同时自带火焰图输出功能，无需通过中间文件来二次转换，结合python灵活特性，适合用于此类问题的精准追踪。

# 2、coolbpf 对perfevent支持
&emsp;perf event 核心配置在于 配置下发 perf\_event\_attr 结构体，参考 [perf 说明](https://man7.org/linux/man-pages/man2/perf_event_open.2.html)。coolbpf 针对 perf_event_attr 结构体进行了python化转化，使用户可以按照python的习惯进行配置，attach上对应的bpf代码就可以运行。比如定期热点采样，可以按照以下代码进行配置：

```
	pfConfig = {
            "sample_freq": self._freq,
            "freq": 1,
            "type": PerfType.SOFTWARE,
            "config": PerfSwIds.CPU_CLOCK,
        }
```
&emsp;coolbpf pylcc perf api 列表：

```
def attachPerfEvent(self, function, attrD, pid=0, cpu=-1, group_fd=-1, flags=0):
def attachAllCpuPerf(self, function, attrD, pid=-1, group_fd=-1, flags=0):
def attachPerfEvents(self, function, attrD, pid, group_fd=-1, flags=0):
def attachJavaSym(self, function, pid, symbol):
```

# 3、perfSys 工具说明：
&emsp;perfSys 基于coolbpf pylcc 实现，[工具路径](https://gitee.com/anolis/surftrace/blob/master/tools/pylcc/pytool/perfSys.py)，参数说明：

```
usage: perfSys.py [-h] [-i INTERVAL] [-g GATE] [-s SAMPLE] [-f FREQ]

collect sys high flame svg.

optional arguments:
  -h, --help            show this help message and exit
  -i INTERVAL, --interval INTERVAL
                        system usage sampling interval time, uint second.
  -g GATE, --gate GATE  system usage limit trigger svg.
  -s SAMPLE, --sample SAMPLE
                        perf sample time.
  -f FREQ, --freq FREQ  perf sample frequency.

examples: python perfSys -g 10 -i 3 -s 3 -f 200
```
&emsp;比如 准备每3秒轮询一次(interval) per cpu sys 使用率情况，如果对应cpu sys 高于10%（gate），就开启perf sys 采用，采样频率为200Hz（freq）， 采样时长3秒钟（sample），即可使用以下命令：

```
python perfSys -g 10 -i 3 -s 3 -f 200
```
&emsp;上数值为默认参数，没有变化可以不用配置参数。

## 3.1、故障注入：
&emsp;我们采用注入ko的方法向内核注入sys，注入代码[参考](https://gitee.com/anolis/surftrace/tree/master/tools/module/sysHigh)，执行inject 以后，sys会直接冲高到60%。

## 3.2、结果验证：
&emsp;可以在故障注入前执行 python perfSys，此时如果sys 不高于门限，不会输出svg。注入sys高后，即可生成svg文件，文件名为sys高产生的时间点，火焰图标题 sysHigh for cpu x\:x\:x，cpu号用冒号隔开。
[参考结果](https://gitee.com/anolis/surftrace/blob/master/tools/module/sysHigh/20221020_145304.svg)


