# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     baseParser
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'


class CbaseParser(object):
    def __init__(self):
        pass

    def _checkRes(self, res):
        return res['log'] == 'ok.' and len(res['res']) > 0

    def getFunc(self, func, ret=None, arg=None):
        return None

    def getStruct(self, sStruct):
        return None

    def getType(self, t):
        return None


if __name__ == "__main__":
    pass
