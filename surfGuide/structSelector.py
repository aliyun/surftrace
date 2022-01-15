# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     structSelector
   Description :
   Author :       liaozhaoyan
   date：          2021/12/17
-------------------------------------------------
   Change Activity:
                   2021/12/17:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
from .conBase import CconBase, log

FILTERT_MAX = 16

class CstructSelctor(CconBase):
    def __init__(self, tStruct, parent):
        self._tStruct = tStruct
        self._parent = parent
        super(CstructSelctor, self).__init__()
        self._filter = ""
        self._memShow = ""

    def _cb_focus_change(self, last, now):
        self._setupMemShow(now)
        self._setFooter("focus change, last, %d, now, %d" % (last, now))

    def _setupMemShow(self, sel):
        cell = self._tStruct["cell"][sel]
        name = cell['name']
        if "[" in name:
            name, arr = name.split("[", 1)
            # notes = f"{name} type:{cell['type']} [{arr}; offset:{cell['offset']}; size:{cell['size']}"
            notes = "%s: type:%s [%s; offset:%d; size:%d" % (name, cell['type'], arr, cell['offset'], cell['size'])
        else:
            # notes = f"{name} type:{cell['type']}; offset:{cell['offset']}; size:{cell['size']}"
            notes = "%s: type:%s; offset:%d; size:%d" % (name, cell['type'], cell['offset'], cell['size'])
        self._memShow = notes

    def _setFooter(self, txt):
        s = "%s\n%s" % (txt, self._memShow)
        self._footer.set_text(s)

    def _cb_esc(self):
        self.switch_widget(self._parent)

    def _cb_mem_change(self, w, stat):
        if stat:
            sel = self._radioGrp.index(w)
            self._setMember(sel)

    def setupView(self):
        self._setupHeadFoot("select %s member" % self._tStruct['name'], "to select a member")

        blank = urwid.Divider()

        info = "    %s: contains %d member, %d bytes" % (self._tStruct['name'], self._tStruct['members'], self._tStruct['size'])
        info += "\n    press 'esc' key to return; any ascii to set filter; 'tab' key to select the next match; 'backspace' key to backspace filter; " \
                "'enter' or 'blank' to select member"
        lStruct = urwid.AttrWrap(urwid.Text(info), "body")

        self._rbList = []
        for cell in self._tStruct["cell"]:
            name = cell['name']
            if "[" in name:
                name, arr = name.split("[", 1)
            self._rbList.append(name)
        sel = 0
        self._setupMemShow(sel)
        self._radioWids, self._radioGrp = self._create_radios(self._rbList, sel=-1, cb=self._cb_mem_change, cb_focus=self._cb_focus_change)
        title = urwid.AttrWrap(urwid.Text("member:", align="right"), "body")
        choose = urwid.Columns([("weight", 1, title),
                                ("weight", 3, self._radioWids)])

        frame = self._setupFrame([lStruct, blank, choose], 2)
        self._setFooter("to select a member")
        return frame

    def _getFocusMember(self):
        return self._radioWids.focus_position
        # self._footer.set_text(f"now focus index: {index}, name: {self._tStruct['cell'][index]['name']}")

    def _setFocusMember(self, index):
        # wid = self._radioGrp[index]
        self._radioWids.set_focus(index)

    def _findMatch(self, index, add):
        start = index + add
        if start < len(self._rbList):
            l1 = self._rbList[start:]
            for i, s in enumerate(l1):
                if s.find(self._filter) >= 0:
                    return start + i
        l2 = self._rbList[:start]
        for i, s in enumerate(l2):
            if s.find(self._filter) >= 0:
                return i
        return -1

    def _filterMatch(self, add=0):
        index = self._getFocusMember()
        res = self._findMatch(index, add)
        if res == -1:
            self._setFooter("filter: %s, can not match any members." % self._filter)
        elif res != index:
            self._setFocusMember(res)  
        self._setFooter("filter: %s, match member %d" % (self._filter, res))

    def _addFilter(self, ch):
        if len(self._filter) < FILTERT_MAX:
            self._filter += ch
            self._filterMatch()

    def _backFilter(self):
        if self._filter != "":
            self._filter = self._filter[:-1]
            self._filterMatch()

    def _setMember(self, sel):
        # index = self._getRadioSelect(self._radioGrp)
        index = sel
        txt = self._tStruct["cell"][index]['name']
        if '[' in txt:
            txt = txt.split('[')[0]
            self._parent.addMem(txt + "[]")
        else:
            self._parent.addMem(txt)
        self._cb_esc()

    def key_proc(self, key):
        if len(key) == 1:
            if key.isalpha():
                self._addFilter(key.lower())
        elif key == 'backspace':
            self._backFilter()
        elif key == 'tab':
            self._filterMatch(add=1)
        elif key == 'esc':
            self._cb_esc()

if __name__ == "__main__":
    pass
