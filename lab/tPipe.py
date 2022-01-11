# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     tPipe
   Description :
   Author :       liaozhaoyan
   date：          2022/1/9
-------------------------------------------------
   Change Activity:
                   2022/1/9:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
import os
import shlex
from subprocess import PIPE, Popen

class ExecException(Exception):
    def __init__(self, message):
        super(ExecException, self).__init__(message)
        self.message = message

class CexecCmd(object):
    def __init__(self, pathOut=None, pathErr=None):
        self._pathOut = pathOut
        self._pathErr = pathErr
        pass

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        return p.stdout.read().strip()

    def system(self, cmds):
        ret = ""
        setCmd = cmds.replace('\0', '').strip()
        oFlag = False; eFlag = False
        if self._pathOut and "1>" not in setCmd:
            if os.path.exists(self._pathOut):
                os.remove(self._pathOut)
            setCmd += " 1>%s" % self._pathOut
            fifoOut = os.open(self._pathOut, os.O_CREAT | os.O_RDONLY | os.O_NONBLOCK)
            oFlag = True
        if self._pathErr and "2>" not in cmds:
            if os.path.exists(self._pathErr):
                os.remove(self._pathErr)
            setCmd += " 2>%s" % self._pathErr
            fifoErr = os.open(self._pathErr, os.O_CREAT | os.O_RDONLY | os.O_NONBLOCK)
            eFlag = True
        os.system(setCmd)
        if oFlag:
            ret = os.read(fifoOut, 4096)
            os.remove(self._pathOut)
        if eFlag:
            err = os.read(fifoErr, 1024)
            os.remove(self._pathErr)
            if len(err):
                raise ExecException("exec cmd %s error, log %s." % (cmds, err.replace('\n', '  ')))
        return ret

if __name__ == "__main__":
    c = CexecCmd(pathOut="/tmp/surfOut", pathErr="/tmp/surfErr")
    print c.system("df -h")
    print c.system("df -r")