# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     lbcBase
   Description :
   Author :       liaozhaoyan
   date：          2021/7/20
-------------------------------------------------
   Change Activity:
                   2021/7/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import json
import hashlib
import signal
import cffi
from threading import Thread
from multiprocessing import cpu_count
from pylcc.lbcMaps import mapsDict
from surftrace.execCmd import CexecCmd
from surftrace.surfException import InvalidArgsException, RootRequiredException, FileNotExistException, DbException
from surftrace.lbcClient import ClbcClient, segDecode
from surftrace.surfCommon import taskList
from surftrace.uprobeParser import CuprobeParser
from pylcc.lbcInclude import ClbcInclude
from pylcc.perfEvent import *

LBC_COMPILE_PORT = 7655


def getCwd(pathStr):
    return os.path.split(os.path.realpath(pathStr))[0]


class ClbcLoad(object):
    def __init__(self, bpf, bpf_str="",
                 server="pylcc.openanolis.cn",
                 arch="", ver="", env="",
                 workPath=None, incPath=None,
                 logLevel=-1, btf=True,
                 opt="so",
                 ):
        if "LBC_SERVER" in os.environ:
            server = os.environ["LBC_SERVER"]
        if "LBC_LOGLEVEL" in os.environ:
            logLevel = int(os.environ["LBC_LOGLEVEL"])
        if workPath:
            self._wPath = workPath
        else:
            self._wPath = os.getcwd()
        self._incPath = incPath

        super(ClbcLoad, self).__init__()

        self._ffi = cffi.FFI()
        self._so = None
        self._need_deinit = False
        self._server = server
        self._c = CexecCmd()
        if btf:
            self._checkRoot()
        self._env = env
        self._logLevel = logLevel

        if ver == "":
            ver = self._c.cmd('uname -r')
        if arch == "":
            arch = self._c.cmd('uname -m')

        if btf:
            self._checkBtf(ver, arch)
        if bpf.endswith(".bpf.c"):
            bpf = bpf[:-6]
        if opt == "so":
            self._getSo(bpf, bpf_str, ver, arch)
        elif opt == "obj":
            self._compileObj(bpf, bpf_str, ver, arch)
        elif opt == "combine":
            pass

    def __del__(self):
        if self._so:
            self._closeSo()

    def _deinitSo(self):
        self._checkSo()
        self._so.lbc_bpf_exit()
        self._need_deinit = False

    def _closeSo(self):
        if self._need_deinit:
            self._deinitSo()
        self._ffi.dlclose(self._so)

    def _checkBtf(self, ver, arch):
        if os.path.exists('/sys/kernel/btf/vmlinux'):
            return
        name = "/boot/vmlinux-%s" % ver
        if not os.path.exists(name):
            cli = ClbcClient(server=self._server, ver=ver, arch=arch)
            dRecv = cli.getBtf()
            if dRecv['btf'] is None:
                print("get btf failed, log is:\n%s" % dRecv['log'])
                raise InvalidArgsException("get btf failed.")
            print("get btf from remote success.")
            with open(name, 'wb') as f:
                f.write(segDecode(dRecv['btf']))

    def _setupSoName(self, bpf):
        return self._wPath + '/' + bpf + ".so"

    def _setUpCode(self, bpf, s):
        if s == "":
            bpf_c = self._wPath + '/' + bpf + ".bpf.c"
            if os.path.exists(bpf_c):
                with open(bpf_c, "r") as f:
                    s = f.read()

    def _getSo(self, bpf, s, ver, arch):
        bpf_so = self._setupSoName(bpf)

        if s == "":
            bpf_c = self._wPath + '/' + bpf + ".bpf.c"
            if os.path.exists(bpf_c):
                with open(bpf_c, "r") as f:
                    s = f.read()
        need = self._checkStrCompile(s, bpf_so, ver, arch)
        if need:
            self._compileSo(s, bpf_so, ver, arch)

    def _checkCCompile(self, bpf_c, bpf_so, ver, arch):
        cFlag = os.path.exists(bpf_c)
        oFlag = os.path.exists(bpf_so)
        if not (cFlag or oFlag):  # is not exist
            raise FileNotExistException("bpf.c or so is not in this dictionary.")
        elif not oFlag and cFlag:  # only bpf.c
            return True
        elif oFlag and not cFlag:  # only so, should check version
            if self._checkVer(bpf_so, ver, arch):
                raise FileNotExistException("bad bpf.so and not bpf.c")
            return False
        else:  # both bpf.c and bo, check hash and version
            with open(bpf_c, "r") as f:
                s = f.read()
            s += self._env
            if sys.version_info.major >= 3:
                cHash = hashlib.sha256(s.encode()).hexdigest()
            else:
                cHash = hashlib.sha256(s).hexdigest()
            if self._checkHash(bpf_so, cHash):
                return True
            return self._checkVer(bpf_so, ver, arch)

    def _checkStrCompile(self, s, bpf_so, ver, arch):
        oFlag = os.path.exists(bpf_so)
        if not oFlag:  # only string
            return True
        elif s == "":  # only so, no string.
            return False
        else:  # both bpf.c and bo, check hash and version
            s = self._combineSource(s)
            s += self._env
            if sys.version_info.major >= 3:
                cHash = hashlib.sha256(s.encode()).hexdigest()
            else:
                cHash = hashlib.sha256(s).hexdigest()
            if self._checkHash(bpf_so, cHash):
                return True
            return self._checkVer(bpf_so, ver, arch)

    def _parseVer(self, ver):
        major, minor, _ = ver.split(".", 2)
        return major

    def _checkVer(self, bpf_so, ver, arch):
        """if should compile return ture, else return false"""
        try:
            self._so = self._ffi.dlopen(bpf_so)
        except (OSError, FileNotFoundError):
            return True
        soVer = self._loadDesc()['kern_version']
        self._closeSo()

        soMajor = self._parseVer(soVer)
        hMajor = self._parseVer(ver)
        return (int(soMajor) > 3) ^ (int(hMajor) > 3)

    def _checkHash(self, bpf_so, cHash):
        """if should compile return ture, else return false"""
        try:
            self._so = self._ffi.dlopen(bpf_so)
        except (OSError, FileNotFoundError):
            return True
        self._ffi.cdef(self._cdef(), override=True)
        soHash = self._loadDesc()['hash']
        self._closeSo()
        return not cHash == soHash

    def _checkRoot(self):
        cmd = 'whoami'
        line = self._c.cmd(cmd).strip()
        if line != "root":
            raise RootRequiredException('this app need run as root')

    def _combineSource(self, s):
        inc = ClbcInclude(self._wPath, self._incPath)
        return inc.parse(s)

    def _compileSo(self, s, bpf_so, ver, arch):
        cli = ClbcClient(server=self._server, ver=ver, arch=arch, port=LBC_COMPILE_PORT)
        dRecv = cli.getC(s, self._env)
        if dRecv is None:
            raise Exception("receive error")
        if dRecv['so'] is None:
            print("compile failed, log is:\n%s" % dRecv['clog'])
            raise InvalidArgsException("compile failed.")
        print("remote server compile success.")
        with open(bpf_so, 'wb') as f:
            f.write(segDecode(dRecv['so']))

    def _compileObj(self, bpf, bpf_str, ver, arch):
        if bpf_str == "":
            cName = bpf + ".bpf.c"
            if not os.path.exists(cName):
                raise InvalidArgsException("file %s is not exist." % cName)
            with open(cName, 'r') as f:
                bpf_str = f.read()

        objName = bpf + ".bpf.o"
        cli = ClbcClient(server=self._server, ver=ver, arch=arch, port=LBC_COMPILE_PORT)
        s = self._combineSource(bpf_str)
        dRecv = cli.getObj(s, self._env)
        if dRecv is None:
            raise Exception("receive error")
        if dRecv['obj'] is None:
            print("compile failed, log is:\n%s" % dRecv['clog'])
            raise InvalidArgsException("compile failed.")
        print("remote server compile success.")
        with open(objName, 'wb') as f:
            f.write(segDecode(dRecv['obj']))

    def _loadSo(self, bpf_so):
        self._so = self._ffi.dlopen(bpf_so)
        self._ffi.cdef(self._cdef(), override=True)

    @staticmethod
    def _cdef():
        return """
        int  lbc_bpf_init(int log_level, int attach);
        void lbc_bpf_exit(void);
        int  lbc_bpf_get_maps_id(char* event);
        int  lbc_set_event_cb(int id,
                       void (*cb)(void *ctx, int cpu, void *data, unsigned int size),
                       void (*lost)(void *ctx, int cpu, unsigned long long cnt));
        int  lbc_event_loop(int id, int timeout);
        int  lbc_map_lookup_elem(int id, const void *key, void *value);
        int  lbc_map_lookup_elem_flags(int id, void *key, void *value, unsigned long int);
        int  lbc_map_lookup_and_delete_elem(int id, void *key, void *value);
        int  lbc_map_delete_elem(int id, void *key);
        int  lbc_map_update_elem(int id, void *key, void *value);
        int  lbc_map_get_next_key(int id, void *key, void *next_key);
        int  lbc_attach_perf_event(const char* func, const char* attr_string, int pid, int cpu, int group_fd, int flags);
        int  lbc_attach_kprobe(char* func, char* sym);
        int  lbc_attach_kretprobe(char* func, char* sym);
        int  lbc_attach_uprobe(char* func, int pid, char *binary_path, unsigned long func_offset);
        int  lbc_attach_uretprobe(char* func, int pid, char *binary_path, unsigned long func_offset);
        int  lbc_attach_tracepoint(char* func, char *tp_category, char *tp_name);
        int  lbc_attach_raw_tracepoint(char* func, char *tp_name);
        int  lbc_attach_cgroup(char* func, int cgroup_fd);
        int  lbc_attach_netns(char* func, int netns);
        int  lbc_attach_xdp(char* func, int ifindex);
        char* lbc_get_map_types(void);
        """

    def _checkSo(self):
        if not self._so:
            raise InvalidArgsException("so not setup.")

    def _loadDesc(self):
        self._checkSo()
        desc = self.c2str(self._so.lbc_get_map_types())
        return json.loads(desc)

    def _initSo(self, attach=1):
        self._checkSo()
        r = self._so.lbc_bpf_init(self._logLevel, attach)
        if r != 0:
            raise InvalidArgsException("so init failed")
        self._need_deinit = True

    def c2str(self, data):
        return self._ffi.string(data)

    @staticmethod
    def c2list(data):
        arr = []
        for i in range(len(data)):
            arr.append(data[i])
        return arr


class ClbcBase(ClbcLoad):
    def __init__(self, bpf, bpf_str="",
                 server="pylcc.openanolis.cn",
                 arch="", ver="", env="",
                 attach=1, workPath=None
                 ):
        super(ClbcBase, self).__init__(bpf, bpf_str, server, arch, ver,
                                       env, workPath=workPath)
        bpf_so = self._setupSoName(bpf)

        self._loadSo(bpf_so)
        self._initSo(attach)

        self.maps = {}
        self._loadMaps()

        self._cbInterrupt = None

    def so(self):
        return self._so

    def _loadMaps(self):
        d = self._loadDesc()
        self._ffi.cdef("\n".join([d['ffi'], self._cdef()]), override=True)
        tDict = mapsDict
        dMaps = d['maps']
        for k in dMaps.keys():
            t = dMaps[k]['type']
            if t in tDict:
                self.maps[k] = tDict[t](self._so, k, dMaps[k], self._ffi)
            else:
                raise InvalidArgsException("bad type: %s, key: %s" % (t, k))

    def getMap(self, name, data, size):
        try:
            return self.maps[name].event(data)
        except IndexError:
            return None

    # https://man7.org/linux/man-pages/man2/perf_event_open.2.html
    def attachPerfEvent(self, function, attrD, pid=0, cpu=-1, group_fd=-1, flags=0):
        for k, v in attrD.items():  # json int type not support 64 bit
            if type(v) is not str:
                try:
                    attrD[k] = "%d" % v
                except TypeError:
                    print("key %s type is %s, not support, skip." % (k, type(v)))
                    del attrD[k]
        attrs = json.dumps(attrD)
        res = self._so.lbc_attach_perf_event(function.encode(), attrs.encode(), pid, cpu, group_fd, flags)
        if res != 0:
            raise InvalidArgsException("attach %s to perf event failed." % function)
        return res

    def attachAllCpuPerf(self, function, attrD, pid=-1, group_fd=-1, flags=0):
        nr_cpu = cpu_count()
        for i in range(nr_cpu):
            self.attachPerfEvent(function, attrD, pid=pid, cpu=i, group_fd=group_fd, flags=flags)

    def attachPerfEvents(self, function, attrD, pid, group_fd=-1, flags=0):
        p = taskList(pid)
        for pthread in p.threads():
            self.attachPerfEvent(function, attrD, pid=pthread.id, cpu=-1, group_fd=group_fd, flags=flags)

    def attachJavaSym(self, function, pid, symbol):
        pFile = "/tmp/perf-%d.map" % pid
        if not os.path.exists(pFile):
            raise InvalidArgsException("can not find java maps for pid %d." % pid)

        syms = []
        with open(pFile, 'r') as f:
            for line in f.readlines():
                start, size, sym = line.split(' ', 2)
                d = {"start": int(start, 16),
                     "size": int(size, 16),
                     'sym': sym.strip(),
                     }
                syms.append(d)

        res = None
        for symd in syms:
            if symd['sym'] == symbol:
                res = symd
                break
        if res is None:
            raise InvalidArgsException("symbol %s is not in map." % symbol)
        addr = res["start"] + 0x20

        pfConfig = {
            "type": PerfType.BREAKPOINT,
            "size": PERF_ATTR_SIZE_VER5,
            "sample_period": 1,
            "precise_ip": 2,
            "wakeup_events": 1,
            "bp_type": PerfBreakPointType.X,
            "bp_addr": addr,
            "bp_len": 8,
        }
        self.attachPerfEvents(function, pfConfig, pid)

    def attachKprobe(self, function, symbol):
        res = self._so.lbc_attach_kprobe(function, symbol)
        if res != 0:
            raise InvalidArgsException("attach %s to kprobe %s failed." % (function, symbol))

    def attachKretprobe(self, function, symbol):
        res = self._so.lbc_attach_kretprobe(function, symbol)
        if res != 0:
            raise InvalidArgsException("attach %s to kretprobe %s failed." % (function, symbol))

    def attachUprobe(self, function, pid, binaryPath, offset=0):
        res = self._so.lbc_attach_uprobe(function, pid, binaryPath, offset)
        if res != 0:
            raise InvalidArgsException("attach %s to uprobe %s failed." % (function, binaryPath))

    def attachUprobes(self, function, pid, binaryPath, offset=0):
        if pid > 0:
            p = taskList(pid)
            for pthread in p.threads():
                self.attachUprobe(function, pthread.id, binaryPath, offset)
        else:
            self.attachUprobe(function, pid, binaryPath, offset)

    def attachUretprobe(self, function, pid, binaryPath, offset=0):
        res = self._so.lbc_attach_uretprobe(function, pid, binaryPath, offset)
        if res != 0:
            raise InvalidArgsException("attach %s to uretprobe %s failed." % (function, binaryPath))

    def attachUretprobes(self, function, pid, binaryPath, offset=0):
        if pid > 0:
            p = taskList(pid)
            for pthread in p.threads():
                self.attachUretprobe(function, pthread.id, binaryPath, offset)
        else:
            self.attachUretprobe(function, pid, binaryPath, offset)

    def traceUprobes(self, function, pid, fxpr):
        binaryPath, func = fxpr.split(":", 1)
        parser = CuprobeParser(binaryPath)
        fullPath = parser.fullObj()
        offset = int(parser.funAddr(func), 16)
        print(fullPath, offset)
        self.attachUprobes(function, pid, fullPath, offset)

    def traceUretprobes(self, function, pid, fxpr):
        binaryPath, func = fxpr.split(":", 1)
        parser = CuprobeParser(binaryPath)
        fullPath = parser.fullObj()
        offset = parser.funAddr(func)
        self.attachUretprobes(function, pid, fullPath, offset)

    def attachTracepoint(self, function, category, name):
        res = self._so.lbc_attach_tracepoint(function, category, name)
        if res != 0:
            raise InvalidArgsException("attach %s to trace point %s failed." % (function, name))

    def attachRawTracepoint(self, function, name):
        res = self._so.lbc_attach_raw_tracepoint(function, name)
        if res != 0:
            raise InvalidArgsException("attach %s to raw trace point %s failed." % (function, name))

    def attachCgroup(self, function, fd):
        res = self._so.lbc_attach_cgroup(function, fd)
        if res != 0:
            raise InvalidArgsException("attach %s to cgroup %d failed." % (function, fd))

    def attachNetns(self, function, fd):
        res = self._so.lbc_attach_netns(function, fd)
        if res != 0:
            raise InvalidArgsException("attach %s to netns %d failed." % (function, fd))

    def attachXdp(self, function, ifindex):
        res = self._so.lbc_attach_xdp(function, ifindex)
        if res != 0:
            raise InvalidArgsException("attach %s to xdp %d failed." % (function, ifindex))

    def _signalInterrupt(self, signum, frame):
        self._cbInterrupt()

    def waitInterrupt(self, cb=None):
        if cb:
            self._cbInterrupt = cb
            signal.signal(signal.SIGINT, self._signalInterrupt)
        signal.pause()


class CeventThread(Thread):
    def __init__(self, lbc, event, cb, lost=None):
        super(CeventThread, self).__init__()
        self.setDaemon(True)
        self._lbc = lbc
        self._event = event
        self._cb = cb
        self.lost = lost
        self.start()

    def cb(self, cpu, data, size):
        e = self._lbc.getMap(self._event, data, size)
        self._cb(cpu, e)

    def run(self):
        self._lbc.maps[self._event].open_perf_buffer(self.cb, lost=self.lost)
        self._lbc.maps[self._event].perf_buffer_poll()


if __name__ == "__main__":
    pass
