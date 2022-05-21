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
from .baseParser import CbaseParser
from .execCmd import CexecCmd
from .surfException import DbException

LBC_COMPILE_PORT = 7655


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
            raise DbException('db set return %s' % ret["log"])
        return ret

    def getFunc(self, func, ret=None, arg=None):
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
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "struct",
                 "struct": sStruct}
        return self._post(dSend)

    def getType(self, t):
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


if __name__ == "__main__":
    pass
