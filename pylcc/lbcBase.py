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
import base64
import ctypes as ct
import _ctypes as _ct
import time
import json
import socket
import hashlib
from pylcc.lbcMaps import CmapsEvent, CmapsHash, CmapsLruHash, CmapsPerHash, CmapsLruPerHash, CmapsStack
from pylcc.lbcMaps import CtypeData
from pylcc.localExceptions import InvalidArgsException, RootRequiredException, FileNotExistException
from surftrace import CexecCmd

ON_POSIX = 'posix' in sys.builtin_module_names

buffSize = 10 * 1024 * 1024

coreDs = {
    "4+19": "4.19.91-21.al7.x86_64",
    "4+9": "4.9.168-016.ali3000.alios7.x86_64",
    "3+10": "3.10.0-1127.el7.x86_64",
}

class ClbcBase(object):
    def __init__(self, bpf, bpf_str="", server="http://pylcc.openanolis.cn/", ver="", env="", workPath=None):
        save = None
        if workPath:
            save = os.getcwd()
            os.chdir(workPath)
        super(ClbcBase, self).__init__()
        self.__need_del = False
        self._server = server
        self._c = CexecCmd()
        self.__checkRoot()
        self._env = env
        bpf_so = self.__getSo(bpf, bpf_str, ver)

        self.__loadSo(bpf_so)
        self.maps = {}
        self._loadMaps()
        if save:
            os.chdir(save)

    def __del__(self):
        if self.__need_del:
            self.__so.lbc_bpf_exit()

    @staticmethod
    def _closeSo(so):
        _ct.dlclose(so._handle)

    def __getSo(self, bpf, s, ver):
        bpf_so = bpf + ".so"
        if ver == "":
            ver = self._c.cmd('uname -r')

        need = False
        if s == "":
            bpf_c = bpf + ".bpf.c"
            if self.__checkCCompile(bpf_c, bpf_so, ver):
                with open(bpf_c, 'r') as f:
                    s = f.read()
                need = True
        else:
            need = self.__checkStrCompile(s, bpf_so, ver)
        if need:
            self._compileSo(s, bpf_so, ver)
        return bpf_so

    def __checkCCompile(self, bpf_c, bpf_so, ver):
        cFlag = os.path.exists(bpf_c)
        oFlag = os.path.exists(bpf_so)
        if not (cFlag or oFlag):  # is not exist
            raise FileNotExistException("bpf.c or so is not in this dictionary.")
        elif not oFlag and cFlag:  # only bpf.c
            return True
        elif oFlag and not cFlag:  # only so, should check version
            if self.__checkVer(bpf_so, ver):
                raise FileNotExistException("bad bpf.so and not bpf.c")
            return False
        else:  # both bpf.c and bo, check hash and version
            with open(bpf_c, "r") as f:
                s = f.read()
            cHash = hashlib.sha256(s.encode('utf-8')).hexdigest()
            if self.__checkHash(bpf_so, cHash):
                return True
            return self.__checkVer(bpf_so, ver)

    def __checkStrCompile(self, s, bpf_so, ver):
        oFlag = os.path.exists(bpf_so)
        if not oFlag:  # only string
            return True
        else:  # both bpf.c and bo, check hash and version
            cHash = hashlib.sha256(s).hexdigest()
            if self.__checkHash(bpf_so, cHash):
                return True
            return self.__checkVer(bpf_so, ver)

    def __parseVer(self, ver):
        major, minor, _ = ver.split(".", 2)
        return major + "+" + minor

    def __checkVer(self, bpf_so, ver):
        """if should compile return ture, else return false"""
        try:
            so = ct.CDLL("./" + bpf_so)
        except:
            return True
        so.lbc_get_map_types.restype = ct.c_char_p
        so.lbc_get_map_types.argtypes = []
        s = so.lbc_get_map_types()
        uname = json.loads(s)['kern_version']
        self._closeSo(so)
        return not self.__parseVer(uname) == self.__parseVer(ver)

    def __checkHash(self, bpf_so, cHash):
        """if should compile return ture, else return false"""
        try:
            so = ct.CDLL("./" + bpf_so)
        except:
            return True
        so.lbc_get_map_types.restype = ct.c_char_p
        so.lbc_get_map_types.argtypes = []
        s = so.lbc_get_map_types()
        soHash = json.loads(s)['hash']
        self._closeSo(so)
        return not cHash == soHash

    def __checkRoot(self):
        cmd = 'whoami'
        line = self._c.cmd(cmd).strip()
        if line != "root":
            raise RootRequiredException('this app need run as root')

    @staticmethod
    def _recv_lbc(s):
        d = s.recv(buffSize).decode("utf-8")
        if d[:3] != "LBC":
            print("not lbc")
            return None
        size = d[3:11]
        try:
            size = int(size, 16) + 11
        except:
            print("bad size", size)
            return None
        while len(d) < size:
            d += s.recv(buffSize).decode("utf-8")
        return json.loads(d[11:])

    @staticmethod
    def _send_lbc(s, send):
        send = "LBC%08x" % (len(send)) + send
        s.send(send.encode('utf-8'))

    def _compileSo(self, s, bpf_so, ver):
        ver = coreDs[self.__parseVer(ver)]
        dSend = {'c': s, 'ver': ver, 'env': self._env}
        send = json.dumps(dSend)
        addr = (self._server, 7655)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(addr)
        self._send_lbc(s, send)
        dRecv = self._recv_lbc(s)
        s.close()
        if dRecv['so'] is None:
            print("compile failed, log is:\n%s" % dRecv['log'])
            raise InvalidArgsException("compile failed.")
        print("remote server compile success.")
        with open(bpf_so, 'wb') as f:
            f.write(base64.b64decode(dRecv['so']))

    def __loadSo(self, bpf_so):
        self.__need_del = True
        self.__so = ct.CDLL("./" + bpf_so)
        self.__so.lbc_bpf_init.restype = ct.c_int
        r = self.__so.lbc_bpf_init()
        if r != 0:
            self.__need_del = False
            raise InvalidArgsException("so init failed")

    def _loadMaps(self):
        self.__so.lbc_get_map_types.restype = ct.c_char_p
        self.__so.lbc_get_map_types.argtypes = []
        s = self.__so.lbc_get_map_types()
        d = json.loads(s)['maps']
        tDict = {'event': CmapsEvent, 'hash': CmapsHash, 'lruHash': CmapsLruHash, 'perHash': CmapsPerHash,
                 'lruPerHash': CmapsLruPerHash, 'stack': CmapsStack, }
        for k in d.keys():
            t = d[k]['type']
            if t in tDict:
                self.maps[k] = tDict[t](self.__so, k, d[k])
            else:
                raise InvalidArgsException("bad type: %s, key: %s" % (t, k))

class ClbcApp(ClbcBase):
    def __init__(self, soPath):
        super(ClbcApp, self).__init__(soPath)

    def _callback(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['my_map'].event(stream)
        print("%d, %s, 0x%x" % (e.pid, e.comm, e.cookie))
        tbl = self.maps['pids'].get()
        if len(tbl) > 20:
            self.maps['pids'].clear()
        print(self.maps['callStack'].getStacks(e.stack_id, 2))

    def loop(self):
        self.maps['my_map'].open_perf_buffer(self._callback)
        try:
            self.maps['my_map'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()

if __name__ == "__main__":
    a = ClbcApp('lbc')
    a.loop()
