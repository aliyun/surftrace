# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     editJprobe
   Description :
   Author :       liaozhaoyan
   date：          2021/12/25
-------------------------------------------------
   Change Activity:
                   2021/12/25:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
import urwid
from .surfExpression import maxNameString, unpackRes, probeReserveVars
from .conBase import CconBase, log
from .argsGuide import CargsGuide
from .editFilter import CeditFilter

class CeditJprobe(CconBase):
    def __init__(self, parent, res, index):
        self._parent = parent
        self._res = res
        self._index = index
        super(CeditJprobe, self).__init__()

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _cb_conform_clk(self, widget):
        self._res['symbol'] = self._eFunc.get_text()[0]
        s = unpackRes(self._res)
        self._parent.setLines(self._index, s)
        self.switch_widget(self._parent)

    def _cb_edit_event(self, widget, text):
        self._footer.set_text("func: %s" % text)

    def _get_filter_func(self, fs, num=5):
        r = ""
        for i, f in enumerate(fs):
            r += '%s,' % f["func"]
            if i == num - 1:
                break
        return r[:-1]

    def _cb_args_clk(self, widget):
        func = self._eFunc.get_text()[0]
        res = self.dbGetFun(func)
        if res['log'] == "ok.":
            fs = res['res']
            if len(fs):
                args = CargsGuide(fs[0], self, self._res)
                self.switch_widget(args)
            else:
                self._footer.set_text("!!!func: %s is not in vmlinux." % func)
        else:
            self._footer.set_text("!!!query function failed: %s" % res['log'])

    def _cb_filter_clk(self, widget):
        filter = CeditFilter(self, self._res, probeReserveVars)
        self.switch_widget(filter)

    def _cb_key_tab(self):
        func = self._eFunc.get_text()[0]
        func = re.sub(r"%+", "%", func)
        if func != "" and func != "%":
            if not func.endswith("%"):
                func += "%"
            res = self.dbGetFun(func)
            if res['log'].startswith("ok"):
                fs = res['res']
                if len(fs) > 0:
                    count = 0
                    show = "functions: "
                    for f in fs:
                        show += f['func'] + " "
                        count += 1
                        if count > 5:
                            break
                    if count == 1:
                        sFunc = fs[0]['func']
                        self._eFunc.set_edit_text(sFunc)
                        self._eFunc.set_edit_pos(len(sFunc) + 1)
                    else:
                        self._footer.set_text(show)
                        sFunc = maxNameString(fs, 'func')
                        self._eFunc.set_edit_text(sFunc)
                        self._eFunc.set_edit_pos(len(sFunc) + 1)
                self._footer.set_text("func: %s" % self._get_filter_func(fs))
            else:
                self._footer.set_text("!!!tab failed: %s" % res['log'])

    def updateTips(self):
        self._tips.set_text("args:%s\nfilter:%s\nYou can use the tab key to get more magic" %
                                (self._res['args'], self._res['filter']))

    def setupView(self):
        self._setupHeadFoot("input a func to probe.",
                            "input a func to probe, mode %s, index: %d." % (self._res['type'], self._index))
        dummy = urwid.Divider()

        lFunc = urwid.AttrWrap(urwid.Text("input a function:", align="right"), "body")
        self._eFunc = self._create_edit("", self._res['symbol'], self._cb_edit_event)
        edits = urwid.Columns([("weight", 1, lFunc),
                               ("weight", 3, self._eFunc),])

        self._tips = urwid.Text("args:%s\nfilter:%s\nYou can use the tab key to get more magic" %
                                         (self._res['args'], self._res['filter']))
        tips = urwid.AttrWrap((self._tips), "body")

        argsButton = self._create_button("[a]rgs", self._cb_args_clk)
        filterBtn = self._create_button("[f]ilter", self._cb_filter_clk)
        btns1 = urwid.Columns([dummy, argsButton, dummy, filterBtn])

        cancelButton = self._create_button("ca[n]cel", self._cb_cancel_clk)
        conformBtn = self._create_button("sav[e]", self._cb_conform_clk)
        btns2 = urwid.Columns([cancelButton, dummy, conformBtn])

        return self._setupFrame([dummy, edits, dummy, tips, dummy, btns1, dummy, btns2])

    def key_proc(self, key):
        if key == "tab":
            self._cb_key_tab()

if __name__ == "__main__":
    pass
