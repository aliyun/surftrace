# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     pure
   Description :
   Author :       liaozhaoyan
   date：          2022/12/4
-------------------------------------------------
   Change Activity:
                   2022/12/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import cffi
import ctypes as ct


class Cpure(object):
    def __init__(self):
        super(Cpure, self).__init__()
        self._ffi, self._so = self._loadSo()
        self._v = 0

    def _loadSo(self):
        ffi = cffi.FFI()
        so = ffi.dlopen("./libbase.so")
        ffi.cdef("""
                void user_add(int a, int b);
                int user_cb(int (*func)(int, int), int a, int b);   
                """)
        return ffi, so

    def user_add(self, a, b):
        self._so.user_add(a, b)

    def closures(self, x, y):
        t = self

        @self._ffi.callback("int(int, int)")
        def _cb(a, b):
            t._v += a + b
            return t._v - 1

        res = self._so.user_cb(_cb, x, y)
        print(res, self._v)


if __name__ == "__main__":
    p = Cpure()
    p.user_add(1, 2)
    p.closures(1, 2)
    p.closures(3, 4)
    pass
