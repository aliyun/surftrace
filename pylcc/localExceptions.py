# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     localExceptions
   Description :
   Author :       liaozhaoyan
   date：          2021/7/20
-------------------------------------------------
   Change Activity:
                   2021/7/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

class FileNotExistException(Exception):
    def __init__(self, msg=""):
        super(FileNotExistException, self).__init__(msg)

class FileNotEmptyException(Exception):
    def __init__(self, msg=""):
        super(FileNotEmptyException, self).__init__(msg)

class InvalidArgsException(Exception):
    def __init__(self, msg=""):
        super(InvalidArgsException, self).__init__(msg)

class RootRequiredException(Exception):
    def __init__(self, msg=""):
        super(RootRequiredException, self).__init__(msg)

if __name__ == "__main__":
    pass
