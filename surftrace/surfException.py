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


class RootRequiredException(Exception):
    def __init__(self, message):
        super(RootRequiredException, self).__init__(message)
        self.message = message


class FileNotExistException(Exception):
    def __init__(self, message):
        super(FileNotExistException, self).__init__(message)
        self.message = message


class FileNotEmptyException(Exception):
    def __init__(self, message):
        super(FileNotEmptyException, self).__init__(message)
        self.message = message


class InvalidArgsException(Exception):
    def __init__(self, message):
        super(InvalidArgsException, self).__init__(message)
        self.message = message


class DbException(Exception):
    def __init__(self, message):
        super(DbException, self).__init__(message)
        self.message = message


class ExprException(Exception):
    def __init__(self, message):
        super(ExprException, self).__init__(message)
        self.message = message


class ExecException(Exception):
    def __init__(self, message):
        super(ExecException, self).__init__(message)
        self.message = message


if __name__ == "__main__":
    pass
