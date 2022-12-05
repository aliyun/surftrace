# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ffiObj
   Description :
   Author :       liaozhaoyan
   date：          2022/12/5
-------------------------------------------------
   Change Activity:
                   2022/12/5:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import cffi
from pylcc.lbcMaps import CffiObj


class Ctest(object):
    def __init__(self, soPath="./libbase.so"):
        self._ffi, self._so = self._loadSo(soPath)

    def _loadSo(self, soPath):
        ffi = cffi.FFI()
        so = ffi.dlopen(soPath)
        ffi.cdef("""
                typedef long unsigned int u64;
                struct struct_child{
                    int a;
                    int b;
                };
                struct struct_user{
                    struct struct_child childs[2];
                    struct struct_child child;
                    struct struct_child* pchild;
                    int a;
                    int b;
                    char s[16];
                    char ss[4][16];
                    int c[4];
                    void* p;
                    void* pa[4];
                    unsigned char u8;
                    signed char v8;
                    short v16;
                    long long v64;
                    double d;
                    float f;
                };  
                struct struct_arr{
                    int a;
                    int b;
                    char s[16];
                    char ss[4][16];
                    int c[4];
                    int cc[2][2];
                    void* p;
                    void* ps[4];
                    struct struct_child child;
                    struct struct_child childs[2];
                };
                void user_add(int a, int b);
                int user_cb(int (*func)(int, int), int a, int b); 
                """)
        return ffi, so

    def test1(self):
        p = self._ffi.new("struct struct_arr *")
        p.c = [1, 2, 3, 4]
        p.cc = [[1, 2], [3, 4]]
        p.s = "hello."
        p.ss = ["hello.", "ffi.", "go", "gouzi."]
        v = CffiObj(self._ffi)
        o = v.value(p)
        print(o.c, o.s)
        print(o.cc, o.ss)
        print(o.p, o.ps)
        print(o.child.a, o.childs[0])
        print(o)

    def testv(self):
        p = self._ffi.new("u64[63]")
        p[0] = 1234
        print(type(p[0]))
        o = CffiObj(self._ffi)
        print(o.value(p))

    def testp(self):
        p = self._ffi.new("char [16]", "hello.")
        o = CffiObj(self._ffi)
        print(o.value(p))

    def testVoid(self):
        vv = self._ffi.new("void **")
        p = self._ffi.cast("int *", vv)
        o = CffiObj(self._ffi)
        print(o.value(p))

    def test(self):
        p = self._ffi.new("struct struct_user *")
        p.s = "hello."
        p.ss[0] = "world1."
        p.ss[1] = "world2."
        p.ss[2] = "world3."
        p.ss[3] = "world4."
        p.c = [1, 2, 3, 4]
        p.a = 1
        p.b = 2
        p.d = 12.3
        p.f = 365.2
        v = CffiObj(self._ffi)
        o = v.value(p)
        print(self._ffi.getctype(self._ffi.typeof(p.ss)))
        print(self._ffi.typeof(p.pchild), p.pchild)
        print(p.child.a)
        print(p.c)
        print("end struct.")
        print(o.a, o.b, o.d, o.f)
        print(o.s, o.p)

        # c = self._ffi.new("int *", 10)
        # CffiObj(self._ffi, c)


if __name__ == "__main__":
    o = Ctest()
    o.testVoid()
    # o.testp()
    # o.test1()
    pass
