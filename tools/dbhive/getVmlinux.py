# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     getVmlinux
   Description :
   Author :       liaozhaoyan
   date：          2021/12/1
-------------------------------------------------
   Change Activity:
                   2021/12/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import shlex
from subprocess import PIPE, Popen
from getFuncs import CgetVminfo, CgenfuncsDb

HivePath = "/home/vmhive/"
# VMPath = HivePath + "vmlinux/"
# BTFPath = HivePath + "btf/"
# HeadPath = HivePath + "header/"
# FuncPath = HivePath + "funcs/"
# DBPath = HivePath + "db/"
# PackPath = HivePath + "pkg/"

class CexecCmd(object):
    def __init__(self):
        super(CexecCmd, self).__init__()

    @staticmethod
    def cmd(cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        return p.stdout.read().decode().strip()

    @staticmethod
    def system(cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.system(cmds)

class CgetVmlinux(CexecCmd):
    def __init__(self):
        super(CgetVmlinux, self).__init__()

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

    #linux-image-3.13.0-96-generic-dbgsym_3.13.0-96.143_i386.ddeb -> 3.13.0-96-generic
    def _genDebVer(self, name):
        if name.startswith("linux-image-unsigned"):
            _, _, _, n = name.split("-", 3)
        else:
            _, _, n = name.split("-", 2)
        ver, _ = n.split("-dbgsym", 1)
        return ver

    def _copyVmlinuxRpm(self, name, release, arch):
        res = self.cmd("find ./ -name vmlinux").strip("\n")
        ver = self._genRpmVer(name)
        VMPath = HivePath + arch + "/vmlinux/"
        dPath = VMPath + "%s/vmlinux-%s" % (release, ver)
        cmd = "cp %s %s" % (res, dPath)
        self.cmd(cmd)
        return [ver, release, dPath, arch]

    def _copyVmlinuxDeb(self, name, release, arch):
        res = self.cmd("find ./ -name vmlinux*").strip("\n").split('\n')
        for r in res:
            if os.path.isfile(r) and not r.endswith("decompressor"):
                ver = self._genDebVer(name)
                VMPath = HivePath + arch + "/vmlinux/"
                dPath = VMPath + release +"/vmlinux-%s" % ver
                cmd = "cp %s %s" % (r, dPath)
                self.cmd(cmd)
                break
        return [ver, release, dPath, arch]

    def _checkProc(self, name, release, arch):
        if name.endswith(".rpm"):
            ver = self._genRpmVer(name)
        elif name.endswith(".ddeb"):
            ver = self._genDebVer(name)
        else:
            return True
        DBPath = HivePath + arch + "/db/"
        dbPath = DBPath + "%s/info-%s.db" % (release, ver)
        dbJournal = dbPath + "-journal"
        PackPath = HivePath + arch + "/pack/"
        packName = f"{PackPath}/{release}/{name}"

        if os.path.exists(dbPath):
            if not os.path.exists(dbJournal):
                return True
        if os.path.exists(packName):
            workPath = self._prevProc()
            self.cmd(f"cp {packName} ./")
            res = self.__proc_work(name, release, arch)
            self._afterProc(workPath, res)
            return True
        return False

    def __proc_work(self, name, release, arch):
        res = None
        if not os.path.exists(name):
            raise Exception("failed to get file.")
        if name.endswith(".rpm"):
            self.drpm(name)
            res = self._copyVmlinuxRpm(name, release, arch)
        elif name.endswith(".ddeb"):
            self.ddeb(name)
            res = self._copyVmlinuxDeb(name, release, arch)
        return res

    def _proc_work(self, url, name, release, arch):
        self.cmd("axel -n 4 %s" % url)
        PackPath = HivePath + arch + "/pack/"
        self.cmd(f"cp {name} {PackPath}/{release}/")
        return self.__proc_work(name, release, arch)

    def _proc_kos(self, db):
        db.parse_kos('./')

    def _prevProc(self):
        lastWork = os.path.abspath(os.getcwd())
        self.cmd(f"rm -rf {os.getpid()}")
        os.mkdir(f"{os.getpid()}")
        os.chdir(f"{os.getpid()}")
        return lastWork

    def _afterProc(self, lastWork, res):
        db = None
        if res is not None:
            db = self.genOthers(*res)
        if db is not None:
            vmPath = res[2]
            try:
                db.pasrseVmLinux(vmPath)
                self._proc_kos(db)
            except OSError as e:
                print(f"parse {vmPath} report {e}")
        os.chdir(lastWork)
        self.cmd(f"rm -rf {os.getpid()}")

    def proc(self, url, name, release, arch):
        print(f"proc {name}, {arch}")
        if self._checkProc(name, release, arch):
            return

        lastWork = self._prevProc()
        res = self._proc_work(url, name, release, arch)
        self._afterProc(lastWork, res)

    def _genBtfHead(self, ver, release, vmPath, arch):
        BTFPath = HivePath + arch + "/btf/"
        HeadPath = HivePath + arch + "/head/"
        btfPath = BTFPath + "%s/vmlinux-%s" % (release, ver)
        headPath = HeadPath + "%s/vmlinux-%s.h" % (release, ver)
        self.cmd("cp %s %s" % (vmPath, btfPath))
        self.cmd("pahole -J %s" % btfPath)
        self.cmd("llvm-objcopy --only-section=.BTF --set-section-flags .BTF=alloc,readonly --strip-all %s" % btfPath)
        if arch == 'aarch64':
            self.cmd("aarch64-linux-gnu-strip -x %s" % btfPath)
        else:
            self.cmd("strip -x %s" % btfPath)
        if os.path.exists(f"{btfPath}.btf"):
            self.cmd(f"rm -f {btfPath}")
            self.cmd(f"mv {btfPath}.btf {btfPath}")
        self.system("bpftool btf dump file %s format c > %s" % (btfPath, headPath))

    def _getFuns(self, ver, release, vmPath, arch):
        pass

    def _genDb(self, ver, release, arch):
        DBPath = HivePath + arch + "/db/"
        dbPath = DBPath + "%s/info-%s.db" % (release, ver)
        print(f"gen {dbPath}")
        db = CgenfuncsDb(dbPath)
        return db

    def genOthers(self, ver, release, vmPath, arch):
        self._genBtfHead(ver, release, vmPath, arch)
        self._getFuns(ver, release, vmPath, arch)
        return self._genDb(ver, release, arch)

if __name__ == "__main__":
    vm = CgetVmlinux()
    vm.proc(url="https://mirrors.openanolis.cn/anolis/8.4/Plus/x86_64/debug/Packages/kernel-debug-debuginfo-4.19.91-23.4.an8.x86_64.rpm",
            name="kernel-debug-debuginfo-4.19.91-23.4.an8.x86_64.rpm",
            release="anolis",
            arch="x86_64"
            )
    pass
