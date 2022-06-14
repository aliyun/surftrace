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
import json
import hashlib
from pylcc.lbcMaps import CmapsEvent, CmapsHash, CmapsArray, \
    CmapsLruHash, CmapsPerHash, CmapsPerArray, CmapsLruPerHash, CmapsStack
from surftrace.execCmd import CexecCmd
from surftrace.surfException import InvalidArgsException, RootRequiredException, FileNotExistException, DbException
from surftrace.lbcClient import ClbcClient, segDecode
from lbcInclude import ClbcInclude

LBC_COMPILE_PORT = 7655


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

    def _getSo(self, bpf, s, ver, arch):
        bpf_so = self._setupSoName(bpf)

        need = False
        if s == "":
            bpf_c = self._wPath + '/' + bpf + ".bpf.c"
            if self._checkCCompile(bpf_c, bpf_so, ver, arch):
                with open(bpf_c, 'r') as f:
                    s = f.read()
                need = True
        else:
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
        else:  # both bpf.c and bo, check hash and version
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
        s = self._combineSource(s)
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

    def _initSo(self):
        self._checkSo()
        self._so.lbc_bpf_init.restype = ct.c_int
        self._so.lbc_bpf_init.argtypes = [ct.c_int]
        r = self._so.lbc_bpf_init(self._logLevel)
        self._need_deinit = True
        if r != 0:
            raise InvalidArgsException("so init failed")


class ClbcBase(ClbcLoad):
    def __init__(self, bpf, bpf_str="",
                 server="pylcc.openanolis.cn",
                 arch="", ver="", env=""):
        super(ClbcBase, self).__init__(bpf, bpf_str, server, arch, ver,
                                       env)
        bpf_so = self._setupSoName(bpf)
        self._loadSo(bpf_so)
        self._initSo()
        self.maps = {}
        self._loadMaps()

    def _loadMaps(self):
        d = self._loadDesc()['maps']
        tDict = {'event': CmapsEvent,
                 'hash': CmapsHash,
                 'array': CmapsArray,
                 'lruHash': CmapsLruHash,
                 'perHash': CmapsPerHash,
                 'perArray': CmapsPerArray,
                 'lruPerHash': CmapsLruPerHash,
                 'stack': CmapsStack, }
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

if __name__ == "__main__":
    pass