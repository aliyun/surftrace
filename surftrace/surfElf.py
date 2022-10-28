# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfElf
   Description :
   Author :       liaozhaoyan
   date：          2022/10/26
-------------------------------------------------
   Change Activity:
                   2022/10/26:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import ctypes as ct
import _ctypes as _ct
from .lbcClient import ClbcClient, segDecode


class CstructKsym(ct.Structure):
    _fields_ = [("addr", ct.c_ulong), ("name", ct.c_char_p)]


def getCwd(pathStr):
    return os.path.split(os.path.realpath(pathStr))[0]


class CelfBase(object):
    def __init__(self):
        super(CelfBase, self).__init__()
        soPath = os.path.join(getCwd(__file__), "syms.so")
        if not os.path.exists(soPath):
            self._downSo(soPath)
        self._so = ct.CDLL(soPath)
        self._dlsym()

    def _downSo(self, soPath):
        print("download elf so.")
        cli = ClbcClient()
        res = cli.getElfSo()
        if res['log'] != "ok.":
            print("get elf.so failed, return: %s" % res['log'])
            raise IOError("get elf file failed.")

        with open(soPath, 'wb') as f:
            f.write(segDecode(res['so']))

    def __del__(self):
        if hasattr(self, "_so"):
            _ct.dlclose(self._so._handle)

    def _dlsym(self):
        pass


class CelfSym(CelfBase):
    def __init__(self, path):
        super(CelfSym, self).__init__()

        self._path = os.path.abspath(path)
        self._elfMana = self._so.sym_load(self._path)
        self._loadOff = self._so.elf_code_offset(self._elfMana)
        if self._loadOff < 0 or self._elfMana is None:
            raise SystemError("path %s is not an valid elf file, or bfd lib may have bugs." % self._path)

    def __del__(self):
        if hasattr(self, "_elfMana") and self._elfMana is not None:
            self._so.de_mana(self._elfMana)
        super(CelfSym, self).__del__()

    def _dlsym(self):
        self._so.sym_load.restype = ct.c_void_p
        self._so.sym_load.argtypes = [ct.c_char_p]
        self._so.de_mana.restype = None
        self._so.de_mana.argtypes = [ct.c_void_p]
        self._so.elf_code_offset.restype = ct.c_ulong
        self._so.elf_code_offset.argtypes = [ct.c_void_p]
        self._so.sym_search.restype = ct.POINTER(CstructKsym)
        self._so.sym_search.argtypes = [ct.c_void_p, ct.c_ulong]
        self._so.sym_addr.restype = ct.c_ulong
        self._so.sym_addr.argtypes = [ct.c_void_p, ct.c_char_p]

    def symSearch(self, addr):
        if addr > 0:
            p = self._so.sym_search(self._elfMana, addr)
            return p.contents.name.decode(), addr - p.contents.addr
        else:
            return "", -1

    def addr2sym(self, addr):
        addr += self._loadOff
        return self.symSearch(addr)

    def symAddr(self, sym):
        return self._so.sym_addr(self._elfMana, sym)

    def symOffset(self):
        return self._loadOff


class CelfKsym(CelfBase):
    def __init__(self):
        super(CelfKsym, self).__init__()

    def __del__(self):
        if hasattr(self, "_so"):
            self._so.ksym_deinit()
        super(CelfKsym, self).__del__()

    def _dlsym(self):
        self._so.ksym_load.restype = ct.c_int
        res = self._so.ksym_load()
        if res < 0:
            raise SystemError("setup kallsyms return %d" % res)

        self._so.ksym_search.restype = ct.POINTER(CstructKsym)
        self._so.ksym_search.argtypes = [ct.c_ulong]
        self._so.ksym_addr.restype = ct.c_ulong
        self._so.ksym_addr.argtypes = [ct.c_char_p]
        self._so.ksym_deinit.restype = None
        self._so.ksym_deinit.argtypes = None

    def ksymSearch(self, addr):
        if addr > 0:
            p = self._so.ksym_search(addr)
            if p is not None:
                return p.contents.name.decode(), p.contents.addr
        return "", -1

    def ksymAddr(self, sym):
        return self._so.ksym_addr(sym)


if __name__ == "__main__":
    pass
