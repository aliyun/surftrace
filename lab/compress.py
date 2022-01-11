# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     compress
   Description :
   Author :       liaozhaoyan
   date：          2022/1/8
-------------------------------------------------
   Change Activity:
                   2022/1/8:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
from zlib import decompress, compress, Z_BEST_COMPRESSION
import json

def saveConf(d, fName):
    sJson = json.dumps(d)
    sComp = compress(sJson, Z_BEST_COMPRESSION)
    with open(fName, 'wb') as f:
        f.write(sComp)

def loadConf(fName):
    with open(fName, 'rb') as f:
        sComp = f.read()
    sJson = decompress(sComp)
    return json.loads(sJson)

if __name__ == "__main__":
    with open('test.json', 'r') as f:
        d = json.load(f)
    saveConf(d, "t.out")
    print loadConf("t.out")
    pass
