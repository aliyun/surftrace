# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     testFFIObj
   Description :
   Author :       liaozhaoyan
   date：          2022/10/13
-------------------------------------------------
   Change Activity:
                   2022/10/13:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import cffi
from pylcc.lbcMaps import CffiTrans

ffi = cffi.FFI()
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
            struct {
                int aa;
                int bb;
            }b;
            int c[4];
            void* p;
            void* pa[4];
            
            char s[16];
            char ss[4][16];
            
            union {
                unsigned int a;
                unsigned short b;
            }u;
            
            unsigned char u8;
            signed char v8;
            short v16;
            long long v64;
            double d;
            float f;
            };
        union union_user{
            unsigned long a;
            unsigned int b;
            unsigned short c;
            unsigned char d;
            unsigned char e[4];
        };
        """)

obj = CffiTrans(ffi)

print("base type..")
int_v = ffi.new("int *", 0x55aa55aa)
assert (obj.value(int_v) == 0x55aa55aa)

char_v = ffi.new("char *", 'c')
assert (obj.value(char_v) == 'c')
uchar_v = ffi.new("unsigned char *", 0xaa)
assert (obj.value(uchar_v) == 0xaa)

short_v = ffi.new("short *", 0x55aa)
assert (obj.value(short_v) == 0x55aa)
ushot_v = ffi.new("unsigned short *", 0xaa55)
assert (obj.value(ushot_v) == 0xaa55)

sint_v = ffi.new("signed int *", 0x55aa55aa)
assert (obj.value(sint_v) == 0x55aa55aa)
uint_v = ffi.new("unsigned int *", 0xaa55aa55)
assert (obj.value(uint_v) == 0xaa55aa55)

u64_v = ffi.new("u64 *", 0x123456789a)
assert (obj.value(u64_v) == 0x123456789a)
int_v = ffi.new("int *", -12345678)
assert (obj.value(int_v) == -12345678)

long_v = ffi.new("long *", 0x55aa55aa55aa55aa)
assert (obj.value(long_v) == 0x55aa55aa55aa55aa)
ulong_v = ffi.new("unsigned long *", 0xaa55aa55aa55aa55)
assert (obj.value(ulong_v) == 0xaa55aa55aa55aa55)

float_v = ffi.new("float *", 3.1415926)
assert (obj.value(float_v) - 3.1415926 < 1e-6)
double_v = ffi.new("double *", -3.1415926)
assert (obj.value(double_v) + 3.1415926 < 1e-6)
print("pass")

print("point type..")   # Users should not access C pointers in python
point = ffi.new("void **")
ffi_p = obj.value(point)
assert (ffi_p.startswith("point:"))

point = ffi.new("char **")
ffi_p = obj.value(point)
assert (ffi_p.startswith("point:"))
print("pass")

print("array type..")
arr = ffi.new("int [4]", [1, 2, 3, 4])
ffiArr = obj.value(arr)
assert (ffiArr[0] == 1)
assert (ffiArr[1] == 2)
assert (ffiArr[2] == 3)
assert (ffiArr[3] == 4)

arr = ffi.new("int [2][2]", [[1, 2], [3, 4]])
ffiArr = obj.value(arr)
assert (ffiArr[0][0] == 1)
assert (ffiArr[0][1] == 2)
assert (ffiArr[1][0] == 3)
assert (ffiArr[1][1] == 4)

s = ffi.new("char [16]", "hello.")
ffs_s = obj.value(s)
assert (ffs_s == "hello.")
print("pass")

print("struct type..")
_struct = ffi.new("struct struct_user *")
_struct.childs[0].a = 1  # struct array
_struct.childs[0].b = 2
_struct.childs[1].a = 3
_struct.childs[1].b = 4
_struct.child.a = 5
_struct.child.b = 6
_struct.a = 1
_struct.b.aa = 2  # anon struct
_struct.b.bb = 3
_struct.c = [1, 2, 3, 4]     # array
_struct.u.a = 0x1234567
_struct.d = 3.1415926
_struct.f = 3.1415926
ffi_struct = obj.value(_struct)
assert (ffi_struct.childs[0].a == 1)
assert (ffi_struct.childs[0].b == 2)
assert (ffi_struct.childs[1].a == 3)
assert (ffi_struct.childs[1].b == 4)
assert (ffi_struct.child.a == 5)
assert (ffi_struct.child.b == 6)
assert (ffi_struct.pchild == "point:struct struct_child *")
assert (ffi_struct.a == 1)
assert (ffi_struct.b.aa == 2)
assert (ffi_struct.b.bb == 3)
assert (ffi_struct.c[0] == 1)
assert (ffi_struct.c[1] == 2)
assert (ffi_struct.c[2] == 3)
assert (ffi_struct.c[3] == 4)
assert (ffi_struct.p.startswith("point:"))
assert (ffi_struct.pa[0].startswith("point:"))
assert (ffi_struct.pa[1].startswith("point:"))
assert (ffi_struct.u.a == 0x1234567)
assert (ffi_struct.u.b == 0x4567)
assert (ffi_struct.d - 3.1415926 < 1e-6)
assert (ffi_struct.f - 3.1415926 < 1e-6)
print("pass")

print("union type..")
_union = ffi.new("union union_user *")
_union.a = 0x123456789abcdef
ffi_union = obj.value(_union)
assert (ffi_union.a == 0x123456789abcdef)
assert (ffi_union.b == 0x89abcdef)
assert (ffi_union.c == 0xcdef)
assert (ffi_union.d == 0xef)
assert (ffi_union.e[0] == 0xef)
assert (ffi_union.e[1] == 0xcd)
print("pass")

if __name__ == "__main__":
    pass
