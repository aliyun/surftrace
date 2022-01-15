# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     editFilter
   Description :
   Author :       liaozhaoyan
   date：          2021/12/29
-------------------------------------------------
   Change Activity:
                   2021/12/29:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
import re
from .conBase import CconBase, log
from .surfExpression import ExprException, stripPoint, splitExpr, isStruct

class CeditFilter(CconBase):
    def __init__(self, parent, res, availVars):
        self._parent = parent
        self._res = res
        self._avialVars = availVars
        self._setupVars()
        super(CeditFilter, self).__init__()

    def _transFilter(self, filter, i, beg):
        decisions = ('==', '!=', '~', '>=', '<=', '>', '<')
        s = filter[beg:i]
        for d in decisions:
            if d in s:
                k, v = s.split(d)
                if k not in self._vars:
                    raise ExprException("var %s is not an available vars." % k)
                return "%s%s%s" % (k, d, v)
        raise ExprException("bad filter format %s" % s)

    def __checkFilter(self, filter):
        cpStr = "()|&"
        beg = 0; ret = ""; l = len(filter)
        for i, c in enumerate(filter):
            if c in cpStr:
                if i and beg != i:
                    ret += self._transFilter(filter, i, beg)
                beg = i + 1
                ret += c
        if beg != l:
            ret += self._transFilter(filter, l, beg)
        return ret

    def _setupVars(self):
        self._vars = tuple(self._avialVars)
        exprs = splitExpr(self._res['args'])
        for expr in exprs:
            var, _ = expr.split("=", 1)
            self._vars += (var,)

    def _checkFilter(self, s):
        try:
            self.__checkFilter(s)
        except ExprException as e:
            self._footer.set_text("%s" % e.message)
            return False
        return True

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _cb_save_clk(self, widget):
        s = self._eFilter.get_text()[0]
        if self._res['type'] in ('p', 'r'):
            if self._checkFilter(s):
                self._res['filter'] = s
                self._parent.updateTips()
                self.switch_widget(self._parent)
        else:   # event will support at next version.
            self._res['filter'] = s
            self._parent.updateTips()
            self.switch_widget(self._parent)

    def _cb_check_filters(self, k):
        s = self._eFilter.get_text()[0]
        if self._checkFilter(s):
            self._footer.set_text("filter check is ok.")

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("set filter, mode: %s" % self._res['type'], "edit.")

        lFilter = urwid.AttrWrap(urwid.Text("args:", align="right"), "body")
        self._eFilter = self._create_edit("", "%s" % self._res['filter'])
        edits = urwid.Columns([('weight', 1, lFilter),
                               ('weight', 4, self._eFilter)])

        s = ""
        for v in self._vars:
            s += "%s " % v
        tips = urwid.AttrWrap(urwid.Text("Available variable: %s" % s), "body")

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_save_clk)
        btns = urwid.Columns([btnCancel, dummy, btnNxt])

        self._regShortCtrl('k', self._cb_check_filters, sendKey=True)
        frame = self._setupFrame([edits, dummy, tips, dummy, btns])
        return frame

if __name__ == "__main__":
    pass
