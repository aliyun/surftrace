# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     packProduct
   Description :
   Author :       liaozhaoyan
   date：          2022/1/10
-------------------------------------------------
   Change Activity:
                   2022/1/10:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import requests
import urwid
from conBase import CconBase, log
from surfThread import CsurfThread

verUrl = "http://pylcc.openanolis.cn/version/x64.txt"

class CpackProduct(CconBase):
    def __init__(self, parent, content):
        self._parent = parent
        self._content = content
        self._vers = requests.get(verUrl).content
        super(CpackProduct, self).__init__()

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("productivity tools", "set regular expression to filter version.")

        lFilter = urwid.AttrWrap(urwid.Text("path:", align="right"), "body")
        self._eFilter = self._create_edit("", "")
        edits = urwid.Columns([('weight', 1, lFilter),
                               ('weight', 4, self._eFilter)])

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_cancel_clk)
        btns = urwid.Columns([btnCancel, dummy, btnNxt])



if __name__ == "__main__":
    pass
