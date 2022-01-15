# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     typeChooser
   Description :
   Author :       liaozhaoyan
   date：          2021/12/25
-------------------------------------------------
   Change Activity:
                   2021/12/25:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
from .conBase import CconBase, log
from .editJprobe import CeditJprobe
from .editEvent import CeditEvent

class CtypeChooser(CconBase):
    def __init__(self, parent):
        self._parent = parent
        super(CtypeChooser, self).__init__()

    def _cb_nxt_clk(self, widget):
        types = ('p', 'r', 'e')
        i = self._getRadioSelect(self._radioGrp)
        res = {'type': types[i], 'symbol': "", 'args': "", 'filter': ""}
        # self._footer.set_text(f"choose {i}, {self._rbList[i]}")
        if res['type'] in ('p', 'r'):
            w = CeditJprobe(self._parent, res, -1)  # jprobe
            self.switch_widget(w)
        else:
            w = CeditEvent(self._parent, res, -1)
            self.switch_widget(w)

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def setupView(self):
        self._setupHeadFoot("select a event type.", "select a event type.")
        dummy = urwid.Divider()

        self._rbList = ["(j)probe", "k(r)etprobe", "(e)vents"]
        self._radioWids, self._radioGrp = self._create_radios(self._rbList)
        label = urwid.AttrWrap(urwid.Text("event type:", align="right"), "body")
        choose = urwid.Columns([label, self._radioWids, dummy])

        nxtButton = self._create_button("n[e]xt", self._cb_nxt_clk, shortcut='n')
        cancelButton = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btns = urwid.Columns([cancelButton, dummy, nxtButton])

        return self._setupFrame([dummy, choose, dummy, btns])

    def key_proc(self, key):
        # self._footer.set_text(f"{key} press, shortcuts: {CconBase.shortKeys}")
        pass

if __name__ == "__main__":
    pass
