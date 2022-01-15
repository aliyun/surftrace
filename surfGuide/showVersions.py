# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     showVersions
   Description :
   Author :       liaozhaoyan
   date：          2022/1/11
-------------------------------------------------
   Change Activity:
                   2022/1/11:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
from .conBase import CconBase, log

class CshowVersions(CconBase):
    def __init__(self, parent, vers):
        self._parent = parent
        self._vers = vers
        super(CshowVersions, self).__init__()

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("matches release versions", "There are a total of %d matching versions" % len(self._vers))

        matches = "regular expression match %d version:\n" % len(self._vers)
        for ver in self._vers:
            matches += "   %s: %s\n" % (ver['arch'], ver['ver'])
        match = urwid.AttrWrap(urwid.Text(matches), "body")

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btns = urwid.Columns([btnCancel, dummy, dummy])
        frame = self._setupFrame([dummy, match, dummy, btns])
        return frame

    def key_proc(self, key):
        if key == "esc":
            self._cb_cancel_clk(None)
            return

if __name__ == "__main__":
    pass
