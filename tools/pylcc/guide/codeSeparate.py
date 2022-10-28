# -*- coding: utf-8 -*-
# cython:language_level=2
"""
-------------------------------------------------
   File Name：     eventOut
   Description :
   Author :       liaozhaoyan
   date：          2021/11/3
-------------------------------------------------
   Change Activity:
                   2021/11/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from pylcc.lbcBase import ClbcBase, CeventThread


class codeSeparate(ClbcBase):
    def __init__(self):
        super(codeSeparate, self).__init__("independ")

    def _cb(self, cpu, e):
        print("cpu: %d current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            cpu, e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def loop(self):
        CeventThread(self, 'e_out', self._cb)
        self.waitInterrupt()


if __name__ == "__main__":
    e = codeSeparate()
    e.loop()
