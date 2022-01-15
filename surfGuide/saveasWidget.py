# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     saveasWidget
   Description :
   Author :       liaozhaoyan
   date：          2021/12/29
-------------------------------------------------
   Change Activity:
                   2021/12/29:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
import os
import urwid
from .conBase import CconBase, log

class CsaveasWidget(CconBase):
    def __init__(self, parent, fName, content):
        self._parent = parent
        self._fName = fName
        self._content = content
        super(CsaveasWidget, self).__init__()
        self._reFile = re.compile(r"[\w][\w._]*[\w]")

    def _cb_magic_key(self, k):
        self._footer.set_text("last file, %s" % self._fName)

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _cb_save_clk(self, widget):
        name = self._ePath.get_edit_text()
        if os.path.isdir(name):
            self._footer.set_text("%s is a path" % name)
            return
        if '/' not in name:
            d = "./"
        else:
            d, name = name.rsplit('/', 1)
        m = self._reFile.match(name)
        if m and len(m[0]) == len(name):
            path = os.path.join(d, name)
            if not path.endswith(".surf"):
                path += ".surf"
            with open(path, 'w') as f:
                f.write(self._content)
            self.switch_widget(self._parent)
        else:
            self._footer.set_text("%s, bad name" % name)

    def _cb_key_tab(self):
        # path = self._ePath.get_text()[0]
        self._footer.set_text("Tab feature will be improved in the next hairstyle version")

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("save as..", "last file, %s" % self._fName)

        lPath = urwid.AttrWrap(urwid.Text("path:", align="right"), "body")
        self._ePath = self._create_edit("", "%s" % self._fName)
        edits = urwid.Columns([('weight', 1, lPath),
                               ('weight', 4, self._ePath)])

        self._regShortCtrl('m', self._cb_magic_key, sendKey=True)

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_save_clk)
        btns = urwid.Columns([btnCancel, dummy, btnNxt])

        frame = self._setupFrame([edits, dummy, btns])
        return frame

    def key_proc(self, key):
        if key == "tab":
            self._cb_key_tab()

if __name__ == "__main__":
    pass
