# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     reFactory
   Description :
   Author :       liaozhaoyan
   date：          2022/1/23
-------------------------------------------------
   Change Activity:
                   2022/1/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re

reSquareBrackets = re.compile(r"(?<=\[).+?(?=\])")
hook = "hooks[]"
res = reSquareBrackets.findall(hook)
print(res, len(res))

if __name__ == "__main__":
    pass
