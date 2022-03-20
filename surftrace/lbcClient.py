# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     lbcClient
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
import json
import socket
from .baseParser import CbaseParser
from .execCmd import CexecCmd
from .surfException import DbException

LBC_COMPILE_PORT = 7654
LBCBuffSize = 80 * 1024 * 1024


class ClbcClient(CbaseParser):
    def __init__(self, server="pylcc.openanolis.cn", ver="", arch=""):
        super(ClbcClient, self).__init__()
        if "LBC_SERVER" in os.environ:
            server = os.environ["LBC_SERVER"]
        c = CexecCmd()
        if ver == "":
            ver = c.cmd('uname -r')
        if arch == "":
            arch = self._getArchitecture(c)
        self._server = server
        self._ver = ver
        self._arch = arch
        self._fastOff = False

    def _getArchitecture(self, c):
        return c.cmd('uname -m')

    def _setupSocket(self):
        addr = (self._server, LBC_COMPILE_PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(addr)
        except socket.gaierror:
            raise DbException("cannot connect remote server:%s" % self._server)
        return s

    @staticmethod
    def _send_lbc(s, send):
        send = "LBC%08x" % (len(send)) + send
        s.send(send.encode())

    @staticmethod
    def _recv_lbc(s):
        if sys.version_info.major == 2:
            d = s.recv(LBCBuffSize)
        else:
            d = s.recv(LBCBuffSize).decode()
        if d[:3] != "LBC":
            return None
        size = d[3:11]
        try:
            size = int(size, 16) + 11
        except:
            raise DbException("bad lbc Exception, %s" % size)
        if size > LBCBuffSize:
            return None
        while len(d) < size:
            if sys.version_info.major == 2:
                d += s.recv(LBCBuffSize)
            else:
                d += s.recv(LBCBuffSize).decode()
        res = json.loads(d[11:])
        if res['log'] != "ok.":
            raise DbException('db set return %s' % res["log"])
        return res

    def getFunc(self, func, ret=None, arg=None):
        s = self._setupSocket()
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "func",
                 "func": func}
        if ret:
            dSend['ret'] = ret
        if arg:
            dSend['arg'] = arg
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getStruct(self, sStruct):
        s = self._setupSocket()
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "struct",
                 "struct": sStruct}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getType(self, t):
        s = self._setupSocket()
        if "*" in t:
            t = '_'
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "type",
                 "type": t}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)


if __name__ == "__main__":
    pass
