# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     execCmd
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
import shlex
from subprocess import PIPE, Popen
from threading import Thread
import select

from .surfException import FileNotExistException
ON_POSIX = 'posix' in sys.builtin_module_names


class CasyncPipe(Thread):
    def __init__(self, f, func):
        if not os.path.exists(f):
            FileNotExistException("%s is not exist." % f)
        self.__callBack = func
        super(CasyncPipe, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__pipe = open(f, 'r')
        self.__loop = True
        self.start()

    def newCb(self, func):
        self.__callBack = func

    def run(self):
        while self.__loop:
            line = self.__pipe.readline().strip()
            self.__callBack(line)

    def terminate(self):
        self.__loop = False
        self.join(1)


class CexecCmd(object):
    def __init__(self):
        pass

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        if sys.version_info.major == 2:
            return p.stdout.read().strip()
        else:
            return p.stdout.read().decode().strip()

    def system(self, cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.popen(cmds).read(8192)


class CasyncCmdQue(object):
    def __init__(self, cmd):
        super(CasyncCmdQue, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, close_fds=ON_POSIX)
        self.__e = select.epoll()
        self.__e.register(self.__p.stdout.fileno(), select.EPOLLIN)

    def __del__(self):
        self.__p.kill()

    def write(self, cmd):
        try:
            self.__p.stdin.write(cmd.encode())
            self.__p.stdin.flush()
        except IOError:
            return -1

    def writeLine(self, cmd):
        self.write(cmd + "\n")

    def read(self, tmout=0.2, l=16384):
        while True:
            es = self.__e.poll(tmout)
            if not es:
                return ""
            for f, e in es:
                if e & select.EPOLLIN:
                    if sys.version_info.major == 2:
                        s = os.read(f, l)
                    else:
                        s = os.read(f, l).decode()
                    return s

    def readw(self, want, tries=100):
        i = 0
        r = ""
        while i < tries:
            line = self.read()
            if want in line:
                return r + line
            r += line
            i += 1
        raise Exception("get want args %s overtimes" % want)

    def terminate(self):
        self.__p.terminate()
        return self.__p.wait()


if __name__ == "__main__":
    pass
