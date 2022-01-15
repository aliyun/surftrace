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

import json
import os
import sys
import re
from re import error as reError
import requests
import urwid
from .conBase import CconBase, log
from .showVersions import CshowVersions
from .publish import Cpublish

verUrl = "http://pylcc.openanolis.cn/version/"
SHOW_VERS = 8

class CpackProduct(CconBase):
    def __init__(self, parent, lines, fName):
        self._parent = parent
        self._lines = lines
        self._fName = fName
        self._vers = {}
        self._filter = ""
        self._matches = []
        super(CpackProduct, self).__init__()

    def _filterVers(self, filter, vers, res):
        try:
            reVer = re.compile(filter)
        except reError:
            return
        for k, v in vers.items():
            for ver in v:
                r = reVer.search(ver)
                if r:
                    res.append({"arch": k, "ver": ver})
        return res

    def _showVers(self, vers):
        l = len(vers)
        matches = "regular expression match %d version:\n" % l
        if l <= SHOW_VERS:
            for ver in vers:
                matches += "%s: %s\n" % (ver['arch'], ver['ver'])
        else:
            for ver in vers[:SHOW_VERS - 1]:
                matches += "%s: %s\n" % (ver['arch'], ver['ver'])
            matches += "...\nPress Ctrl + ] to show all %d versions.\n" % l
        self._verShow.set_text(matches)

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _matchVers(self):
        t = self._filter
        self._matches = []
        if t:
            res = self._filterVers(t, self._vers, self._matches)
            if res is None:
                self._footer.set_text("%s is an illegal regular expression." % t)
            else:
                self._footer.set_text("filter %s match %d versions" % (t, len(self._matches)))
                self._showVers(self._matches)
        else:
            count = 0
            for k, v in self._vers.items():
                count += len(v)
            self._footer.set_text("remote server has %d versions." % (count))

    def _cb_filter_edit(self, widget, t):
        self._filter = t
        self._matchVers()

    def _cb_show_more(self, key):
        l = len(self._matches)
        if l > SHOW_VERS:
            self._footer.set_text("ok.")
            w = CshowVersions(self, self._matches)
            self.switch_widget(w)
        else:
            self._footer.set_text("There are a total of %d matching versions." % l)

    def _cb_publish(self, widget):
        if len(self._matches):
            w = Cpublish(self, self._lines, self._fName, self._matches)
            self.switch_widget(w)
        else:
            self._footer.set_text("no version match, nothing todo.")

    def __setupVers(self, w, vers):
        arch = w.get_label()
        verList = requests.get("%s%s.txt" % (verUrl, arch)).content.split("\n")[:-1]
        vers[arch] = verList
        return len(verList)

    def _setupVers(self, widget, stat):
        self._vers = {}
        count = 0
        for w in self._archs:
            if w == widget:
                if stat:
                    count += self.__setupVers(w, self._vers)
            elif w.get_state():
                count += self.__setupVers(w, self._vers)
        self._matchVers()


    def _cb_check_change(self, w, stat):
        self._setupVers(w, stat)

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("productivity tools", "")

        lArch = urwid.AttrWrap(urwid.Text("arch:", align="right"), "body")
        cArch, self._archs = self._create_checks(["x86_64", "aarch64"], cb=self._cb_check_change)
        archs = urwid.Columns([lArch, cArch, dummy])
        self._archs[0].set_state(True)

        lFilter = urwid.AttrWrap(urwid.Text("re:", align="right"), "body")
        self._eFilter = self._create_edit("", self._filter, cb=self._cb_filter_edit)
        edits = urwid.Columns([('weight', 1, lFilter),
                               ('weight', 4, self._eFilter)])

        btnPub = self._create_button("[p]ublish", self._cb_publish)
        btnMore = self._create_button("more", self._cb_show_more)
        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_cancel_clk)
        btns1 = urwid.Columns([dummy, btnMore, dummy, btnPub, dummy])
        btns2 = urwid.Columns([dummy, dummy, btnCancel, dummy, btnNxt])

        self._verShow = urwid.Text("version list.")
        verShow = urwid.AttrWrap(self._verShow, "body")
        self._regShortCtrl(']', self._cb_show_more, sendKey=True)

        tips  = "set regular expression to filter, eg:\n"
        tips += "    '.+an' to filter all anolis version.\n"
        tips += "    '3.10' to filter all 3.10 verions.\n"
        wtips = urwid.AttrWrap(urwid.Text(tips), "body")
        frame = self._setupFrame([edits, wtips, dummy, archs, dummy, verShow, btns1, dummy, btns2])
        return frame

if __name__ == "__main__":
    pass
