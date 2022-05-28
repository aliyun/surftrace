# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     prevPareser
   Description :
   Author :       liaozhaoyan
   date：          2022/5/28
-------------------------------------------------
   Change Activity:
                   2022/5/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
from .baseDbParser import CbaseDbParser, DbException


class CprevPareser(CbaseDbParser):
    def __init__(self, dbPath="prev.db"):
        if "LBC_PREVDB" in os.environ:
            dbPath = os.environ["LBC_PREVDB"]
        self.exist = True
        try:
            super(CprevPareser, self).__init__(dbPath)
        except DbException:
            self.exist = False


if __name__ == "__main__":
    pass
