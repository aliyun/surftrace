# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfException
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import traceback


class BaseException(Exception):
    def __init__(self, message):
        super(BaseException, self).__init__(message)
        self.message = message + '\n'
        self.message += traceback.format_exc()


class RootRequiredException(BaseException):
    def __init__(self, message):
        super(RootRequiredException, self).__init__(message)


class FileNotExistException(BaseException):
    def __init__(self, message):
        super(FileNotExistException, self).__init__(message)


class FileNotEmptyException(BaseException):
    def __init__(self, message):
        super(FileNotEmptyException, self).__init__(message)


class InvalidArgsException(BaseException):
    def __init__(self, message):
        super(InvalidArgsException, self).__init__(message)


class DbException(BaseException):
    def __init__(self, message):
        super(DbException, self).__init__(message)


class ExprException(BaseException):
    def __init__(self, message):
        super(ExprException, self).__init__(message)


class ExecException(BaseException):
    def __init__(self, message):
        super(ExecException, self).__init__(message)


if __name__ == "__main__":
    pass
