# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     entry
   Description :
   Author :       liaozhaoyan
   date：          2022/1/20
-------------------------------------------------
   Change Activity:
                   2022/1/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'
try:
    from menus.surfGuide import CsurfGuide
except:
    from surfGuide.menus.surfGuide import CsurfGuide

def main():
    guide = CsurfGuide()
    guide.loop()

if __name__ == "__main__":
    main()
