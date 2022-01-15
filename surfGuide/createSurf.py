# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     creatSurf
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
import re
import urwid
from .conBase import CconBase, log
from .editExpression import CeditExpression

class CcreateSurf(CconBase):
    def __init__(self, dirName):
        self._dir = dirName
        self._reFile = re.compile(r"[\w][\w._]*[\w]")
        super(CcreateSurf, self).__init__()

    def _cb_create_clk(self, widget):
        name = self._eSurf.get_edit_text()
        m = self._reFile.search(name)
        if m and len(m.group()) == len(name):
            path = os.path.join(self._dir, name)
            if not path.endswith(".surf"):
                path += ".surf"
            edit = CeditExpression(path)
            self.switch_widget(edit)
            # self._footer.set_text("path %s is ok" % path)
        else:
            self._footer.set_text("%s, bad name" % name)

    def setupView(self):
        self._setupHeadFoot("input surf name, in path %s" % self._dir, "input a surf file.")

        lSurf = urwid.AttrWrap(urwid.Text("input a file:", align="right"), "body")
        self._eSurf = self._create_edit("", "", None)
        edits = urwid.Columns([("weight", 1, lSurf),
                                ("weight", 3, self._eSurf)])

        createButton = self._create_button("cr[e]ate", self._cb_create_clk)
        btns = urwid.Columns([urwid.Divider(), urwid.Divider(), createButton])

        frame = self._setupFrame([edits, urwid.Divider(), btns])
        return frame

    def key_proc(self, key):
        if key == "enter":
            self._cb_create_clk(None)

if __name__ == "__main__":
    pass
