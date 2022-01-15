# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     editEvent
   Description :
   Author :       liaozhaoyan
   date：          2021/12/30
-------------------------------------------------
   Change Activity:
                   2021/12/30:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
import re
from .conBase import CconBase, log
from .editFilter import CeditFilter
from .surfExpression import ExprException, maxNameString, unpackRes, probeReserveVars

class CeditEvent(CconBase):
    def __init__(self, parent, res, index):
        self._parent = parent
        self._res = res
        self._index = index
        super(CeditEvent, self).__init__()

    def _event_checker(self, txt):
        if '/' not in txt:
            raise ExprException("%s is not an legal event expression." % txt)

    def _cb_key_tab(self):
        self._footer.set_text("Tab feature will be improved in the next hairstyle version")

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _cb_check_event(self, k):
        self._footer.set_text("Check feature will be improved in the next hairstyle version")

    def _cb_save_clk(self, widget):
        self._res['symbol'] = self._eEvent.get_text()[0]
        try:
            self._event_checker(self._res['symbol'])
        except ExprException as e:
            self._footer.set_text(e.message)
            return
        s = unpackRes(self._res)
        self._parent.setLines(self._index, s)
        self.switch_widget(self._parent)

    def _cb_filter_clk(self, widget):
        filter = CeditFilter(self, self._res, probeReserveVars)
        self.switch_widget(filter)

    def updateTips(self):
        pass

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("set filter, mode: %s" % self._res['type'], "edit events.")

        lEvent = urwid.AttrWrap(urwid.Text("args:", align="right"), "body")
        self._eEvent = self._create_edit("", "%s" % self._res['symbol'])
        edits = urwid.Columns([('weight', 1, lEvent),
                               ('weight', 4, self._eEvent)])

        tips = urwid.AttrWrap(urwid.Text("This feature will be improved in the next hairstyle version."), "body")

        filterBtn = self._create_button("[f]ilter", self._cb_filter_clk)
        btns1 = urwid.Columns([dummy, dummy, filterBtn])

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_save_clk)
        btns = urwid.Columns([btnCancel, dummy, btnNxt])

        self._regShortCtrl('k', self._cb_check_event, sendKey=True)
        frame = self._setupFrame([edits, dummy, tips, dummy, btns1, btns])
        return frame

    def key_proc(self, key):
        if key == "tab":
            self._cb_key_tab()

if __name__ == "__main__":
    pass
