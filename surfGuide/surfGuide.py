#!/usr/bin/python
# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     surfGuide
   Description :
   Author :       liaozhaoyan
   date：          2021/12/30
-------------------------------------------------
   Change Activity:
                   2021/12/30:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
sys.path.append("../")
import urwid
import os
from .conBase import CconBase, log
import requests
from .lbcClient import CdbParser, ClbcClient
from surftrace import CexecCmd
from .fileBrowser import CfileBrowser

class CsurfGuide(CconBase):
    def __init__(self):
        super(CsurfGuide, self).__init__()

    def _getFilePath(self, fName):
        path = os.path.abspath(__file__)
        path, _ = path.rsplit("/", 1)
        return path + "/../" + fName

    def _cb_cancel_clk(self, widget):
        self.exit()

    def _cb_download_clk(self, widget):
        c = CexecCmd()
        ver = c.cmd('uname -r')
        fName = self._getFilePath("info-%s.db" % ver)
        if os.path.exists(fName):
            self._footer.set_text("db file %s is already downloaded." % fName)
            return
        url = "http://pylcc.openanolis.cn/db/x86_64/info-%s.db" % ver
        db = requests.get(url)
        with open(fName, "wb") as f:
            f.write(db.content)
        self._footer.set_text("download %s success." % fName)

    def _cb_browse_clk(self, widget):
        c = CexecCmd()
        ver = c.cmd('uname -r')
        fName = self._getFilePath("info-%s.db" % ver)
        if os.path.exists(fName):
            self.setupDb(CdbParser(fName))
        else:
            self.setupDb(ClbcClient())
        w = CfileBrowser()
        self.switch_widget(w)

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("welcome to user surfGuide", "Embark on a ftrace journey")

        s = "The software is released under the GNU LESSER GENERAL PUBLIC LICENSE.\n"
        s += "author: liaozhaoyan\n"
        s += "mail: zhaoyan.lzy@alibaba-inc.com\n"
        s += "\nKeyTips: if a character is in (), eg. (b)rowse, its corresponding shortcut is single 'b'; "
        s += "elif a character is in [], eg. ca[n]cel, its corresponding shortcut is Ctrl + 'n'."
        tips = urwid.AttrWrap(urwid.Text(s), "body")

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnDownload = self._create_button("(d)ownload", self._cb_download_clk)
        btnBrowse = self._create_button("(b)rowse", self._cb_browse_clk)
        btns = urwid.Columns([btnCancel, dummy, btnDownload, dummy, btnBrowse])

        frame = self._setupFrame([dummy, tips, dummy, btns])
        return frame

def main():
    guide = CsurfGuide()
    guide.loop()

if __name__ == "__main__":
    main()