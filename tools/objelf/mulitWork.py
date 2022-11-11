# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     mulitWork
   Description :
   Author :       liaozhaoyan
   date：          2022/11/7
-------------------------------------------------
   Change Activity:
                   2022/11/7:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
import time
import shlex
from subprocess import PIPE, Popen
from multiprocessing import Process
from testDebuginfo import CtestDebug

workPath = "/root/1ext/work"
srcPath = "/root/1ext/vmhive/x86_64/pack"
dstPath = "/root/1ext/nhive/"


class Cwork(Process):
    def __init__(self, path):
        super(Cwork, self).__init__()
        self.daemon = True
        self._path = path
        self.start()

    def system(self, cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        s = p.stdout.read().decode().strip()
        p.wait()
        return s

    def drpm(self, path):
        self.system("rpm2cpio %s|cpio -id" % path)

    def ddeb(self, path):
        self.cmd("ar x %s" % path)
        if os.path.exists("data.tar.xz"):
            self.cmd("xz -d data.tar.xz")
            self.cmd("tar xf data.tar")
        else:
            self.cmd("tar -I zstd -xvf data.tar.zst")

    def _genRpmVer(self, name):
        _, _, n = name.split("-", 2)
        ver, _ = n.rsplit(".", 1)
        return ver

    def _genDebVer(self, name):
        if name.startswith("linux-image-unsigned"):
            _, _, _, n = name.split("-", 3)
        else:
            _, _, n = name.split("-", 2)
        ver, _ = n.split("-dbgsym", 1)
        return ver

    def _dbPath(self, name, release, arch):
        if name.endswith(".rpm"):
            ver = self._genRpmVer(name)
        elif name.endswith(".ddeb"):
            ver = self._genDebVer(name)
        else:
            raise ValueError("bad version.")

        DBPath = dstPath + arch + "/db/"
        return DBPath + "%s/info-%s.db" % (release, ver)

    def _unpack(self, name):
        if name.endswith(".rpm"):
            self.drpm(name)
        elif name.endswith(".ddeb"):
            self.ddeb(name)
        else:
            raise ValueError("bad version.")

    def run(self):
        print(os.getpid(), self._path)
        wPath = os.path.join(workPath, "%d" % os.getpid())
        self.cmd("mkdir %s" % wPath)
        os.chdir(wPath)
        self.cmd("cp %s ./" % self._path)
        _, arch, _, release, name = self._path.rsplit("/", 4)
        db = self._dbPath(name, release, arch)
        print(db)
        self._unpack(name)
        t = CtestDebug("./", db)
        t.work()
        os.chdir(workPath)
        self.cmd("rm -rf %s" % wPath)


def work(path):
    Cwork(path)


class CgroupWork(object):
    def __init__(self, path, maxL=6):
        super(CgroupWork, self).__init__()
        self._path = path
        self._ps = []
        self._max = maxL

    def getPath(self):
        gs = os.walk(self._path)
        for path, dirL, fileL in gs:
            for fName in fileL:
                yield os.path.join(path, fName)

    def check(self):
        if len(self._ps) < self._max:
            return
        while True:
            for i, L in enumerate(self._ps):
                if not L.is_alive():
                    del self._ps[i]
                    return
            time.sleep(1)

    def work(self):
        for path in self.getPath():
            self._ps.append(Cwork(path))
            self.check()


if __name__ == "__main__":
    g = CgroupWork(srcPath, maxL=6)
    g.work()
    pass
