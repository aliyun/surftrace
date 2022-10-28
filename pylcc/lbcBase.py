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
import ctypes as ct
import _ctypes as _ct
import psutil
import json
import hashlib
import signal
from threading import Thread
from multiprocessing import cpu_count
from pylcc.lbcMaps import mapsDict
from surftrace.execCmd import CexecCmd
from surftrace.surfException import InvalidArgsException, RootRequiredException, FileNotExistException, DbException
from surftrace.lbcClient import ClbcClient, segDecode
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
        _ct.dlclose(self._so._handle)
        self._so = None

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
            self._so = ct.CDLL(bpf_so)
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
            self._so = ct.CDLL(bpf_so)
        except (OSError, FileNotFoundError):
            return True
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
        self._so = ct.CDLL(bpf_so)

    def _checkSo(self):
        if not self._so:
            raise InvalidArgsException("so not setup.")

    def _loadDesc(self):
        self._checkSo()
        self._so.lbc_get_map_types.restype = ct.c_char_p
        self._so.lbc_get_map_types.argtypes = []
        desc = self._so.lbc_get_map_types()
        return json.loads(desc)

    def _initSo(self, attach=1):
        self._checkSo()
        self._so.lbc_bpf_init.restype = ct.c_int
        self._so.lbc_bpf_init.argtypes = [ct.c_int, ct.c_int]
        r = self._so.lbc_bpf_init(self._logLevel, attach)
        if r != 0:
            raise InvalidArgsException("so init failed")
        self._need_deinit = True


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
        self._setupAttatchs()
        self._setupOtherSyms()

        self.maps = {}
        self._loadMaps()

        self._cbInterrupt = None

    def so(self):
        return self._so

    def _setupOtherSyms(self):
        self._so.lbc_bpf_get_maps_id.restype = ct.c_int
        self._so.lbc_bpf_get_maps_id.argtypes = [ct.c_char_p]
        self._so.lbc_map_lookup_elem.restype = ct.c_int
        self._so.lbc_map_lookup_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
        self._so.lbc_map_lookup_and_delete_elem.restype = ct.c_int
        self._so.lbc_map_lookup_and_delete_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
        self._so.lbc_map_delete_elem.restype = ct.c_int
        self._so.lbc_map_delete_elem.argtypes = [ct.c_int, ct.c_void_p]
        self._so.lbc_map_get_next_key.restype = ct.c_int
        self._so.lbc_map_get_next_key.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]

        self._so.lbc_event_loop.restype = ct.c_int
        self._so.lbc_event_loop.argtypes = [ct.c_int, ct.c_int]

        eventCallback = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_ulong)
        lostCallback = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_ulonglong)

        self._so.lbc_set_event_cb.restype = ct.c_int
        self._so.lbc_set_event_cb.argtypes = [ct.c_int, eventCallback, lostCallback]

    def _setupAttatchs(self):
        #   int lbc_attach_perf_event(const char* func, const char* attrs, int pid, int cpu, int group_fd)
        self._so.lbc_attach_perf_event.restype = ct.c_int
        self._so.lbc_attach_perf_event.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_int, ct.c_int, ct.c_int, ct.c_int]
        #   int lbc_attach_kprobe(const char* func, const char* sym)
        self._so.lbc_attach_kprobe.restype = ct.c_int
        self._so.lbc_attach_kprobe.argtypes = [ct.c_char_p, ct.c_char_p]
        #   int lbc_attach_kretprobe(const char* func, const char* sym)
        self._so.lbc_attach_kretprobe.restype = ct.c_int
        self._so.lbc_attach_kretprobe.argtypes = [ct.c_char_p, ct.c_char_p]
        #    int lbc_attach_uprobe(const char* func, int pid, const char *binary_path, unsigned long func_offset)
        self._so.lbc_attach_uprobe.restype = ct.c_int
        self._so.lbc_attach_uprobe.argtypes = [ct.c_char_p, ct.c_int, ct.c_char_p, ct.c_ulong]
        #    int lbc_attach_uretprobe(const char* func, int pid, const char *binary_path, unsigned long func_offset)
        self._so.lbc_attach_uretprobe.restype = ct.c_int
        self._so.lbc_attach_uretprobe.argtypes = [ct.c_char_p, ct.c_int, ct.c_char_p, ct.c_ulong]
        #   int lbc_attach_tracepoint(const char* func, const char *tp_category, const char *tp_name)
        self._so.lbc_attach_tracepoint.restype = ct.c_int
        self._so.lbc_attach_tracepoint.argtypes = [ct.c_char_p, ct.c_char_p, ct.c_char_p]
        #   int lbc_attach_raw_tracepoint(const char* func, const char *tp_name)
        self._so.lbc_attach_raw_tracepoint.restype = ct.c_int
        self._so.lbc_attach_raw_tracepoint.argtypes = [ct.c_char_p, ct.c_char_p]
        #   int lbc_attach_cgroup(const char* func, int cgroup_fd)
        self._so.lbc_attach_cgroup.restype = ct.c_int
        self._so.lbc_attach_cgroup.argtypes = [ct.c_char_p, ct.c_int]
        #   int lbc_attach_netns(const char* func, int netns_fd)
        self._so.lbc_attach_netns.restype = ct.c_int
        self._so.lbc_attach_netns.argtypes = [ct.c_char_p, ct.c_int]
        #   int lbc_attach_xdp(const char* func, int ifindex)
        self._so.lbc_attach_xdp.restype = ct.c_int
        self._so.lbc_attach_xdp.argtypes = [ct.c_char_p, ct.c_int]

    def _loadMaps(self):
        d = self._loadDesc()['maps']
        tDict = mapsDict
        for k in d.keys():
            t = d[k]['type']
            if t in tDict:
                self.maps[k] = tDict[t](self._so, k, d[k])
            else:
                raise InvalidArgsException("bad type: %s, key: %s" % (t, k))

    def getMap(self, name, data, size):
        stream = ct.string_at(data, size)
        try:
            return self.maps[name].event(stream)
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
        p = psutil.Process(pid)
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
            p = psutil.Process(pid)
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
            p = psutil.Process(pid)
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
