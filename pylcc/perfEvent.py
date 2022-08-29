# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     perfEvent
   Description :
   Author :       liaozhaoyan
   date：          2022/8/21
-------------------------------------------------
   Change Activity:
                   2022/8/21:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'


class PerfType:
    # From perf_type_id in uapi/linux/perf_event.h
    HARDWARE = 0
    SOFTWARE = 1
    TRACEPOINT = 2
    HW_CACHE = 3
    RAW = 4
    BREAKPOINT = 5
    MAX = BREAKPOINT


class PerfHWConfig:
    # From perf_hw_id in uapi/linux/perf_event.h
    CPU_CYCLES = 0
    INSTRUCTIONS = 1
    CACHE_REFERENCES = 2
    CACHE_MISSES = 3
    BRANCH_INSTRUCTIONS = 4
    BRANCH_MISSES = 5
    BUS_CYCLES = 6
    STALLED_CYCLES_FRONTEND = 7
    STALLED_CYCLES_BACKEND = 8
    REF_CPU_CYCLES = 9
    MAX = REF_CPU_CYCLES


class PerfHWCacheId:
    # From hw_cache_id  in uapi/linux/perf_event.h
    L1D = 0
    L1I = 1
    LL = 2
    DTLB = 3
    ITLB = 4
    BPU = 5
    NODE = 6
    MAX = NODE


class PerfHWCacheOpId:
    # From hw_cache_op_id   in uapi/linux/perf_event.h
    READ = 0
    WRITE = 1
    PREFETCH = 2
    MAX = PREFETCH


class PerfHWCacheOpResultId:
    # From hw_cache_op_result_id    in uapi/linux/perf_event.h
    ACCESS = 0
    MISS = 1
    MAX = MISS


class PerfSwIds:
    # From perf_sw_id in uapi/linux/perf_event.h
    CPU_CLOCK = 0
    TASK_CLOCK = 1
    PAGE_FAULTS = 2
    CONTEXT_SWITCHES = 3
    CPU_MIGRATIONS = 4
    PAGE_FAULTS_MIN = 5
    PAGE_FAULTS_MAJ = 6
    ALIGNMENT_FAULTS = 7
    EMULATION_FAULTS = 8
    DUMMY = 9
    BPF_OUTPUT = 10
    CGROUP_SWITCHES = 11
    MAX = CGROUP_SWITCHES


class PerfEventSampleFormat:
    # From perf_event_sample_format in uapi/linux/perf_event.h
    IP = 1 << 0
    TID = 1 << 1
    TIME = 1 << 2
    ADDR = 1 << 3
    READ = 1 << 5
    CALLCHAIN = 1 << 5
    ID = 1 << 6
    CPU = 1 << 7
    PERIOD = 1 << 8
    STREAM_ID = 1 << 9
    RAW = 1 << 10
    BRANCH_STACK = 1 << 11
    REGS_USER = 1 << 12
    STACK_USER = 1 << 13
    WEIGHT = 1 << 14
    DATA_SRC = 1 << 15
    IDENTIFIER = 1 << 16
    TRANSACTION = 1 << 17
    REGS_INTR = 1 << 18
    PHYS_ADDR = 1 << 19
    AUX = 1 << 20
    CGROUP = 1 << 21
    DATA_PAGE_SIZE = 1 << 22
    CODE_PAGE_SIZE = 1 << 23
    WEIGHT_STRUCT = 1 << 25
    MAX = WEIGHT_STRUCT << 1


PERF_SAMPLE_WEIGHT_TYPE = (PerfEventSampleFormat.WEIGHT | PerfEventSampleFormat.WEIGHT_STRUCT)


class PerfBranchSampleType:
    # from perf_branch_sample_type
    USER = 1 << 0           # /* user branches */
    KERNEL = 1 << 1         # /* kernel branches */
    HV = 1 << 2             # /* hypervisor branches */
    ANY = 1 << 3            # /* any branch types */
    ANY_CALL = 1 << 4       # /* any call branch */
    ANY_RETURN = 1 << 5     # /* any return branch */
    IND_CALL = 1 << 6       # /* indirect calls */
    ABORT_TX = 1 << 7       # /* transaction aborts */
    IN_TX = 1 << 8          # /* in transaction */
    NO_TX = 1 << 9          # /* not in transaction */
    COND = 1 << 10          # /* conditional branches */
    CALL_STACK = 1 << 11    # /* call/ret stack */
    IND_JUMP = 1 << 12      # /* indirect jumps */
    CALL = 1 << 13          # /* direct call */
    NO_FLAGS = 1 << 14      # /* no flags */
    NO_CYCLES = 1 << 15     # /* no cycles */
    TYPE_SAVE = 1 << 16     # /* save branch type */
    HW_INDEX = 1 << 17      # /* save low level index of raw branch records */
    MAX = HW_INDEX << 1


class PerfBranch:
    # Common flow change classification
    UNKNOWN = 0     # /* unknown */
    COND = 1        # /* conditional */
    UNCOND = 2      # /* unconditional */
    IND = 3         # /* indirect */
    CALL = 4        # /* function call */
    IND_CALL = 5    # /* indirect function call */
    RET = 6         # /* function return */
    SYSCALL = 7     # /* syscall */
    SYSRET = 8      # /* syscall return */
    COND_CALL = 9   # /* conditional function call */
    COND_RET = 10   # /* conditional function return */
    MAX = COND_RET


PERF_SAMPLE_BRANCH_PLM_ALL = PerfBranchSampleType.USER | PerfBranchSampleType.KERNEL | PerfBranchSampleType.HV

# /*
#   * The format of the data returned by read() on a perf event fd,
#   * as specified by attr.read_format:
#  *
#  * struct read_format {
#  *      { u64           value;
#  *        { u64         time_enabled; } && PERF_FORMAT_TOTAL_TIME_ENABLED
#  *        { u64         time_running; } && PERF_FORMAT_TOTAL_TIME_RUNNING
#  *        { u64         id;           } && PERF_FORMAT_ID
#  *      } && !PERF_FORMAT_GROUP
#  *
#  *      { u64           nr;
#  *        { u64         time_enabled; } && PERF_FORMAT_TOTAL_TIME_ENABLED
#  *        { u64         time_running; } && PERF_FORMAT_TOTAL_TIME_RUNNING
#  *        { u64         value;
#  *          { u64       id;           } && PERF_FORMAT_ID
#  *        }             cntr[nr];
#  *      } && PERF_FORMAT_GROUP
#  * };
#  */


class PerfEventReadFormat:
    TOTAL_TIME_ENABLED = 1 << 0
    TOTAL_TIME_RUNNING = 1 << 1
    ID = 1 << 2
    GROUP = 1 << 3
    MAX = GROUP


PERF_ATTR_SIZE_VER0 = 64    # /* sizeof first published struct */
PERF_ATTR_SIZE_VER1 = 72    # /* add: config2 */
PERF_ATTR_SIZE_VER2 = 84    # /* add: branch_sample_type */
PERF_ATTR_SIZE_VER3 = 96    # /* add: sample_regs_user */
#                             /* add: sample_stack_user */
PERF_ATTR_SIZE_VER4 = 102   # /* add: sample_regs_intr */
PERF_ATTR_SIZE_VER5 = 114   # /* add: aux_watermark */
PERF_ATTR_SIZE_VER6 = 120   # /* add: aux_sample_size */
PERF_ATTR_SIZE_VER7 = 128   # /* add: sig_data */


if __name__ == "__main__":
    pass
