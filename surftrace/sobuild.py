# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     sobuild
   Description :
   Author :       liaozhaoyan
   date：          2022/7/1
-------------------------------------------------
   Change Activity:
                   2022/7/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import sys
from .kobuild import CkoBuilder


class Csobuid(CkoBuilder):
    def __init__(self):
        super(Csobuid, self).__init__()

    def build(self, iPath, out="user.db"):
        pass


def main():
    k = CkoBuilder()
    k.build(sys.argv[1])


if __name__ == "__main__":
    pass
