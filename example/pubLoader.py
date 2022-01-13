# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     pubLoader
   Description :
   Author :       liaozhaoyan
   date：          2022/1/12
-------------------------------------------------
   Change Activity:
                   2022/1/12:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
from surftrace import surftrace, InvalidArgsException, CexecCmd
import json
from zlib import decompress
from base64 import b64decode

pubString = "to_be_replaced."
class CpubLoader(object):
    def __init__(self, path=None):
        self._surf = None
        self._loadDicts(path)
        super(CpubLoader, self).__init__()

    def _getArchitecture(self, c):
        lines = c.cmd('lscpu').split('\n')
        for line in lines:
            if line.startswith("Architecture"):
                arch = line.split(":", 1)[1].strip()
                if arch.startswith("arm"):
                    return "arm"
                return arch
        return "Unkown"

    def _setupEnvs(self):
        c = CexecCmd()
        ver = c.cmd('uname -r')
        arch = self._getArchitecture(c)
        return ver, arch

    def _setupSurf(self, verD, echo=True):
        if hasattr(self, "_cbOrig"):
            self._surf = surftrace(verD, None, echo=echo, cbOrig=self._cbOrig)
        elif hasattr(self, "_cb"):
            self._surf = surftrace(verD, None, echo=echo, cb=self._cb)
        else:
            self._surf = surftrace(verD, None, echo=echo)

    def _install(self, verD):
        self._setupSurf(verD)

    def _setupVers(self, vers):
        ver, arch = self._setupEnvs()
        vers = vers.split('\n')
        for cell in vers[1:]:
            verD = json.loads(cell)
            if verD['ver'] == ver and verD['arch'] == arch:
                self._install(verD)
                return
        raise InvalidArgsException("arch: %s, version: %s, setup failed." % (arch, ver))

    def _loadPubString(self):
        if pubString == "to_be_replaced.":
            raise InvalidArgsException("args error: you should set a file to load.")
        bin = b64decode(pubString)
        vers = decompress(bin)
        self._setupVers(vers)

    def _loadBin(self, path):
        with open(path, 'rb') as f:
            sComp = f.read()
        vers = decompress(sComp)
        self._setupVers(vers)

    def _loadOrig(self, path):
        ver, arch = self._setupEnvs()
        with open(path, 'r') as f:
            for i, line in enumerate(f):
                if i:
                    verD = json.loads(line)
                    if verD['ver'] == ver and verD['arch'] == arch:
                        self._install(verD)
        raise InvalidArgsException("arch: %s, version: %s, setup failed." % (arch, ver))

    def _loadDicts(self, path):
        if path is None:
            return self._loadPubString()
        elif os.path.exists(path):
            if path.endswith(".orig"):
                return self._loadOrig(path)
            elif path.endswith(".bin"):
                return self._loadBin(path)
        raise InvalidArgsException("")

    def start(self):
        self._surf.start()
        self._surf.loop()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        pub = CpubLoader(sys.argv[1])
    else:
        pub = CpubLoader()
    pub.start()
