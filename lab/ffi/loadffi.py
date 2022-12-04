# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     loadffi.py
   Description :
   Author :       liaozhaoyan
   date：          2022/11/28
-------------------------------------------------
   Change Activity:
                   2022/11/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import ctypes as ct
import cffi

ffi = cffi.FFI()
ffi.cdef("""
struct struct_user{
    int a;
    int b;
    char s[16];
    int c[4];
    void* p;
    double d;
    float f;
};
""")


def c2str(data):
    return ffi.string(data)


def c2list(data):
    arr = []
    for i in range(len(data)):
        arr.append(data[i])
    return arr


def cb_py(p):
    pData = ffi.cast("struct struct_user *", p)
    print(type(pData.s), type(pData.a), type(pData.c))
    print(pData.a, pData.b, c2str(pData.s))
    print(pData.c[1])
    print(pData.p, c2list(pData.c))
    print(pData.d, pData.f)
    return pData.a + pData.b


def load(soPath="./libbase.so"):
    so = ct.CDLL(soPath)
    cbFunc = ct.CFUNCTYPE(ct.c_int, ct.c_void_p)
    so.user_test.restype = ct.c_int
    so.user_test.argtypes = [cbFunc, ct.c_int]

    so.user_add.argtypes = [ct.c_int, ct.c_int]
    so.user_add(3, 4)

    _cb = cbFunc(cb_py)
    print(so.user_test(_cb, 3))

    p = ffi.new("struct struct_user *")
    p.s = "hello."
    print(c2str(p.s))
    c = ffi.new("int *", 10)
    print(int(c))


if __name__ == "__main__":
    load()
    pass
