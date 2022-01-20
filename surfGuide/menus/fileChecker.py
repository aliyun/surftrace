# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     fileChecker
   Description :
   Author :       liaozhaoyan
   date：          2021/12/24
-------------------------------------------------
   Change Activity:
                   2021/12/24:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os

def surfCheck(path):
    if not os.path.isfile(path):
        return "%s is not a regular file, %d." % path
    if not path.endswith(".surf"):
        return "%s may not a surftrace file." % path
    return "ok."

def createSurf(path, name):
    if not name.endswith(".surf"):
        name += ".surf"
    dirName, _ = os.path.split(path)
    fullName = os.path.join(dirName, name)
    if os.path.exists(fullName):
        return "%s is already exist" % fullName
    return fullName

if __name__ == "__main__":
    pass
