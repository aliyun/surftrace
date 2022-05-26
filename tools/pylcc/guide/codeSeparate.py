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

import ctypes as ct
from pylcc.lbcBase import ClbcBase


class codeSeparate(ClbcBase):
    def __init__(self):
        super(codeSeparate, self).__init__("independ")

    def _cb(self, cpu, data, size):
        stream = ct.string_at(data, size)
        e = self.maps['e_out'].event(stream)
        print("current pid:%d, comm:%s. wake_up_new_task pid: %d, comm: %s" % (
            e.c_pid, e.c_comm, e.p_pid, e.p_comm
        ))

    def loop(self):
        self.maps['e_out'].open_perf_buffer(self._cb)
        try:
            self.maps['e_out'].perf_buffer_poll()
        except KeyboardInterrupt:
            print("key interrupt.")
            exit()


if __name__ == "__main__":
    e = codeSeparate()
    e.loop()
