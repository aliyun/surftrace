# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     subProcess
   Description :
   Author :       liaozhaoyan
   date：          2022/1/6
-------------------------------------------------
   Change Activity:
                   2022/1/6:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import signal
import time
import Queue
from multiprocessing import Process
from multiprocessing import Queue as pQueue
from threading import Thread

sys.path.append("..")
from surftrace.surftrace import surftrace, setupParser

class CsubSurf(Process):
    def __init__(self, cmds, log="/dev/null"):
        super(CsubSurf, self).__init__()
        self._q = pQueue(maxsize=20,)
        self._cmds = cmds
        self._log = log

    def _dupStdout(self, fName):
        f_log = open(fName, "w")
        sys.stdout = f_log
        sys.stderr = f_log

    def get(self):
        return self._q.get(block=True)

    def _cb(self, line):
        try:
            self._q.put(line, block=False)
        except Queue.Full:
            pass

    def run(self):
        self._dupStdout(self._log)
        parser = setupParser()
        surf = surftrace(self._cmds, parser, echo=False, cb=self._cb)
        surf.start()
        surf.loop()

    def stop(self):
        os.kill(self.pid, signal.SIGINT)
        self._q.close()  # cease thread loop exit.
        self.join()

class CsurfThread(Thread):
    def __init__(self, cmds, log="/dev/null", cb=None):
        super(CsurfThread, self).__init__()
        self.daemon = True
        self._surf = CsubSurf(cmds, log)
        if cb: self._cb = cb
        else: self._cb = self._defaultCb

    def _defaultCb(self, line):
        print(line)

    def run(self):
        self._surf.start()
        while True:
            try:
                line = self._surf.get()
            except IOError:
                return
            self._cb(line)

    def stop(self):
        self._surf.stop()
        self.join()

def cb(line):
    print("cb." + line)

if __name__ == "__main__":
    t = CsurfThread(["p _do_fork", "p __netif_receive_skb_core proto=@(struct iphdr *)l3%0->protocol ip_src=@(struct iphdr *)%0->saddr ip_dst=@(struct iphdr *)l3%0->daddr data=X@(struct iphdr *)l3%0->sdata[1] f:proto==1&&ip_src==127.0.0.1"], cb=cb)
    t.start()
    time.sleep(10)
    t.stop()
    print("ok.")
    time.sleep(1)
    pass
