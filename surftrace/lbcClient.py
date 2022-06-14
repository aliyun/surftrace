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
import requests
import base64
from .baseParser import CbaseParser
from .prevPareser import CprevPareser
from .execCmd import CexecCmd
from .surfException import DbException

LBC_COMPILE_PORT = 7655

SEG_UNIT = 4096


def segDecode(stream):
    line = b""
    l = len(stream)
    for i in range(0, l, 4 * SEG_UNIT):
        s = stream[i:i + 4 * SEG_UNIT]
        line += base64.b64decode(s)
    if l % (4 * SEG_UNIT):
        i = int(l / (4 * SEG_UNIT) * (4 * SEG_UNIT))
        line += base64.b64decode(stream[i:])
    return line


def segEncode(stream):
    line = b""
    l = len(stream)
    for i in range(0, l, 3 * SEG_UNIT):
        s = stream[i:i+3 * SEG_UNIT]
        line += base64.b64encode(s)
    if l % (3 * SEG_UNIT):
        i = int(l / (3 * SEG_UNIT) * (3 * SEG_UNIT))
        line += base64.b64encode(stream[i:])
    return line


class ClbcClient(CbaseParser):
    def __init__(self, server="pylcc.openanolis.cn", ver="", arch="", port=LBC_COMPILE_PORT):
        super(ClbcClient, self).__init__()
        if "LBC_SERVER" in os.environ:
            server = os.environ["LBC_SERVER"]
        c = CexecCmd()
        if ver == "":
            ver = c.cmd('uname -r')
        if arch == "":
            arch = c.cmd('uname -m')
        self._server = server
        self._ver = ver
        self._arch = arch
        self._fastOff = False
        self._url = "http://%s:%d/lbc" % (server, port)
        self._prev = CprevPareser()

    def _post(self, send, tmo=5):
        cmd = json.dumps([send])
        try:
            res = requests.post(self._url, data=cmd, headers={'Connection': 'close'}, timeout=tmo)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout
                ):
            raise DbException("bad lbc server")
        rd = json.loads(res.text.encode())
        if rd['code'] != 200:
            raise DbException("remote server result %s, text: %s" % res.text)

        ret = rd['res'][0]
        if ret['log'] != 'ok.':
            if 'clog' in ret:
                print("compile failed.\n%s\n" % ret['clog'])
            raise DbException('db set return %s' % ret["log"])
        return ret

    def getFunc(self, func, ret=None, arg=None):
        if self._prev.exist:
            res = self._prev.getFunc(func, ret, arg)
            if self._checkRes(res):
                return res

        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "func",
                 "func": func}
        if ret:
            dSend['ret'] = ret
        if arg:
            dSend['arg'] = arg
        return self._post(dSend)

    def getStruct(self, sStruct):
        if self._prev.exist:
            res = self._prev.getFunc(sStruct)
            if self._checkRes(res):
                return res

        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "struct",
                 "struct": sStruct}
        return self._post(dSend)

    def getType(self, t):
        if self._prev.exist:
            res = self._prev.getType(t)
            if self._checkRes(res):
                return res

        if "*" in t:
            t = '_'
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "type",
                 "type": t}
        return self._post(dSend)

    def getBtf(self):
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "btf",
                 }
        return self._post(dSend)

    def getC(self, code, env):
        dSend = {"cmd": "c",
                 'code': code,
                 'ver': self._ver,
                 'arch': self._arch,
                 'env': env}
        return self._post(dSend, tmo=30)

    def getObj(self, code, env):
        dSend = {"cmd": "obj",
                 'code': code,
                 'ver': self._ver,
                 'arch': self._arch,
                 'env': env}
        return self._post(dSend, tmo=30)

    def koBuild(self, kos):
        if len(kos) < 1:
            raise ValueError("no file to send.")
        dSend = {
            "cmd": "ko",
            "arch": self._arch,
            'ver': self._ver,
            "kos": kos,
        }
        return self._post(dSend, tmo=30)


if __name__ == "__main__":
    pass
