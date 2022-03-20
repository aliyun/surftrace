# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ftrace
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
import signal
import re

from .surfException import RootRequiredException, InvalidArgsException
from .execCmd import CexecCmd, CasyncPipe


save2File = False
cmdStrings = "trap ':' INT QUIT TERM PIPE HUP\n"


def saveCmd(s):
    global save2File
    global cmdStrings
    if save2File:
        cmdStrings += s + "\n"


class ftrace(object):
    def __init__(self, show=False, echo=True, instance="ftrace"):
        super(ftrace, self).__init__()
        self._show = show
        self._echo = echo
        self._c = CexecCmd()
        if not self._show:
            self.__checkRoot()
        self.baseDir = self.__getMountDir()
        self.pipe = None
        self._stopHook = []
        self._single = True
        self.__ps = []

        self._instance = instance
        self._checkIsEmpty()
        # skip 1234.7890: Unknown type 12342
        self._reSkip = re.compile(r"[\d]+\.[\d]+: +Unknown type +[\d]+")

    def __getMountDirStr(self):
        cmd = "mount"
        lines = self._c.cmd(cmd)
        for l in lines.split('\n'):
            if "type debugfs" in l:
                return l
        return None

    def __checkRoot(self):
        cmd = 'whoami'
        line = self._c.cmd(cmd).strip()
        if line != "root":
            raise RootRequiredException('this app need run as root')

    def __getMountDir(self):
        s = self.__getMountDirStr()
        if s is None:
            self._c.cmd("mount -t debugfs none /sys/kernel/debug/")
            s = self.__getMountDirStr()
            if s is None:
                raise InvalidArgsException("mount debugfs failed.")
        return s.split(' ')[2]

    def _checkIsEmpty(self):
        if not os.path.exists(self.baseDir + '/tracing/instances/' + self._instance):
            os.mkdir(self.baseDir + '/tracing/instances/' + self._instance)
        return

    def tracePre(self, buffSize=2048):
        pBuffersize = self.baseDir + "/tracing/instances/%s/buffer_size_kb" % self._instance
        self._echoPath(pBuffersize, "%d" % buffSize)
        pTrace = self.baseDir + "/tracing/instances/%s/trace" % self._instance
        self._echoPath(pTrace)

    def _transEcho(self, value):
        value = re.sub(r"[\"\']", "", value)
        return value

    def _echoPath(self, path, value=""):
        cmd = "echo %s > %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY)
        v = self._transEcho(value)
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, report:%s." % (v, path, e.strerror))
        finally:
            os.close(fd)

    def _echoFilter(self, path, value):
        cmd = "echo %s > %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY)
        v = value[1:-1]
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, report:%s." % (v, path, e.strerror))
        finally:
            os.close(fd)

    def _echoDPath(self, path, value=""):
        cmd = "echo %s >> %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY|os.O_APPEND)
        v = self._transEcho(value)
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, return %s." %(v, path, e.strerror))
        finally:
            os.close(fd)

    def procLine(self, line):
        print(line)
        return 0

    def __stopTracing(self):
        pOn = self.baseDir + "/tracing/instances/%s/tracing_on" % self._instance
        self._echoPath(pOn, "0")

    def _start(self):
        pOn = self.baseDir + "/tracing/instances/%s/tracing_on" % self._instance
        self._echoPath(pOn, "1")
        self._stopHook.insert(0, self.__stopTracing)
        signal.signal(signal.SIGINT, self.signalHandler)

    def start(self):
        self._single = True
        self._start()
        pipe = self.baseDir + "/tracing/instances/%s/trace_pipe" % self._instance
        if hasattr(self, "_cbOrig"):
            self.pipe = CasyncPipe(pipe, self._cbOrig)
        else:
            self.pipe = CasyncPipe(pipe, self.procLine)
        saveCmd("cat %s" % pipe)

    def signalHandler(self, signalNumber, frame):
        if signalNumber == signal.SIGINT:
            self.stop()

    def stop(self):
        if self._single:
            self.pipe.terminate()
        else:
            for p in self.__ps:
                p.join()
        for hook in self._stopHook:
            hook()

    def loop(self):
        signal.pause()


if __name__ == "__main__":
    pass
