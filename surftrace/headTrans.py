# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     headTrans
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import struct
import socket
from .surfException import ExprException


def getValueFromStr(s, isHex=False):
    if isHex or s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    else:
        return int(s)


def _headSplit(head):
    sizeD = {"16": "H", "32": "I", "64": "Q"}
    t, size = head[0], head[1:]
    if size not in sizeD.keys():
        raise ExprException("head type %s is not legal type." % size)
    return t, sizeD[size]


headFlags = ("ip", "b16", "b32", "b64", "B16", "B32", "B64")


def headTrans(head, var):
    h = head.split('_', 1)[0]
    if h not in headFlags:
        varStr = var
    elif h == "ip":
        varInt = getValueFromStr(var)
        varStr = socket.inet_ntoa(struct.pack('>I', socket.htonl(varInt)))
    else:
        t, pt = _headSplit(h)
        varInt = getValueFromStr(var, t == "B")
        varInt = struct.unpack(pt, struct.pack(">" + pt, varInt))
        if t == "B":
            varStr = "%x" % varInt
        else:
            varStr = "%d" % varInt
    return "%s=%s" % (head, varStr)


def _invHead(t, value):
    if t[0] == 'B':
        return "%x" % value
    return "%d" % value


def invHeadTrans(head, var):  #为 filter 翻转
    h = head.split('_', 1)[0]
    if h not in headFlags:
        varStr = var
    elif h == "ip":
        varInt = struct.unpack('I', socket.inet_aton(var))[0]
        varStr = "0x%x" % varInt
    else:
        t, pt = _headSplit(h)
        varInt = getValueFromStr(var, t == "B")
        varInt = struct.unpack(pt, struct.pack('>' + pt, varInt))
        if t == "B":
            varStr = "%x" % varInt
        else:
            varStr = "%d" % varInt
    return head, varStr


if __name__ == "__main__":
    pass
