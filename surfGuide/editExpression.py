# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     editExpression
   Description :
   Author :       liaozhaoyan
   date：          2021/12/24
-------------------------------------------------
   Change Activity:
                   2021/12/24:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import time

sys.path.append("..")

import os
import urwid
from .conBase import CconBase, log
from .typeChooser import CtypeChooser
from .editJprobe import CeditJprobe
from .editEvent import CeditEvent
from .saveasWidget import CsaveasWidget
from .packProduct import CpackProduct
from .surfExpression import *
from .surfThread import CsurfThread

MAX_LINE = 10

class CeditExpression(CconBase):
    def __init__(self, fileName):
        self._fName = fileName
        self._lines = []
        if os.path.exists(fileName):
            with open(fileName, 'r') as f:
                self._lines = f.read().split("\n")
        self._loopBack = []
        self._surf = None
        super(CeditExpression, self).__init__()
        self._surf = None
        self._runWidget = None

    def __del__(self):
        pass

    def _cbSurf(self, line):
        self._addLines(line)
        self._loop.process_input(("surf",))

    def _cb_add_clk(self, widget):
        self._stopSurt()
        w = CtypeChooser(self)
        self.switch_widget(w)

    def _cb_pack_clk(self, widget):
        self._stopSurt()
        if len(self._lines) > 0:
            w = CpackProduct(self, self._lines, self._fName)
            self.switch_widget(w)
        else:
            self._footer.set_text("there is no expression to production.")

    def _cb_save_clk(self, widget):
        self._stopSurt()
        s = "\n".join(self._lines)
        with open(self._fName, "w") as f:
            f.write(s)
        self._footer.set_text("save file ok.")

    def _cb_saveas_clk(self, widget):
        self._stopSurt()
        s = "\n".join(self._lines)
        saveAs = CsaveasWidget(self, self._fName, s)
        self.switch_widget(saveAs)

    def _cb_quit_clk(self, widget):
        self._stopSurt()
        self.exit()

    def setLines(self, index, line):
        if index == -1:
            self._lines.append(line)
        else:
            self._lines[index] = line
        self.fresh()

    def _cb_edit_clk(self, widget):
        self._stopSurt()
        i = self._edits.index(widget)
        line = self._lines[i]
        try:
            res = spiltInputLine(line)
        except ExprException as e:
            self._footer.set_text("expression %s error, %s" % (line, e.message))
            return
        if res['type'] in ('p', 'r'):
            args = CeditJprobe(self, res, i)
            self.switch_widget(args)
        elif res['type'] in ('e',):
            event = CeditEvent(self, res, i)
            self.switch_widget(event)

    def _cb_del_clk(self, widget):
        self._stopSurt()
        i = self._dels.index(widget)
        self._lines.pop(i)
        self.fresh()

    def _startSurf(self, widget):
        widget.set_label("Stop")
        self._runWidget = widget
        i = self._runs.index(widget)
        self._surf = CsurfThread([self._lines[i]], cb=self._cbSurf)
        self._surf.start()
        log(self._lines[i])

    def _stopSurt(self):
        if self._surf:
            self._surf.stop()
            self._surf = None
            self._runWidget.set_label("Run")
            self._runWidget = None

    def _cb_run_clk(self, widget):
        old = self._runWidget
        if self._runWidget:
            self._stopSurt()
        if old != widget:
            self._startSurf(widget)

    def _genTitle(self, l):
        shows = l.split(" ", 2)
        return shows[0] + " " + shows[1]

    def _addLines(self, line):
        if len(self._loopBack) > MAX_LINE - 1:
            self._loopBack.pop()
        self._loopBack.insert(0, line)

    def _getLoopBack(self):
        s = ""
        for l in self._loopBack:
            s += l + "\n"
        return s[:-1]

    def _updateConsole(self):
        self._console.set_text(self._getLoopBack())
        self.redraw()

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("edit surf file %s" % self._fName, "edit file, %s" % self._lines)

        self._esPile = None
        self._es = []
        self._edits = []
        self._dels = []
        self._runs = []
        for line in self._lines:
            label = urwid.AttrWrap(urwid.Text(self._genTitle(line)), "body")
            editButton = self._create_button("Edit", self._cb_edit_clk)
            delButton = self._create_button("Del", self._cb_del_clk)
            runButton = self._create_button("Run", self._cb_run_clk)
            es = urwid.Columns([("weight", 4, label),
                               ("weight", 1, editButton),
                               ("weight", 1, delButton),
                                ("weight", 1, runButton),])
            self._edits.append(editButton.w)
            self._dels.append(delButton.w)
            self._runs.append(runButton.w)
            self._es.append(es)
        if len(self._es):
            self._esPile = urwid.Pile(self._es)

        addButton = self._create_button("[a]dd", self._cb_add_clk)
        adds = urwid.Columns((("weight", 3, dummy),
                               ("weight", 1, addButton),
                              ("weight", 1, dummy),))

        self._console = urwid.Text(self._getLoopBack())
        con = urwid.AttrWrap(self._console, "body")

        saveButton = self._create_button("sav[e]", self._cb_save_clk)
        saveasButton = self._create_button("sav(e) as", self._cb_saveas_clk)
        packButton = self._create_button("[p]ackage", self._cb_pack_clk)
        quitButton = self._create_button("ca[n]cel", self._cb_quit_clk)
        tool1 = urwid.Columns([dummy, dummy, dummy, dummy, packButton])
        tool2 = urwid.Columns([quitButton, dummy, saveasButton, dummy, saveButton])
        if self._esPile:
            return self._setupFrame([self._esPile, dummy, adds, dummy, con, dummy, tool1, dummy, tool2])
        else:
            return self._setupFrame([dummy, adds, dummy, con, dummy, tool1, dummy, tool2])

    def _showLabels(self):
        # self._footer.set_text(f"{self._esPile.contents[0][0].}")
        for i, l in enumerate(self._lines):
            widget = self._esPile.contents[i][0].contents[0][0].w
            widget.set_text(self._genTitle(l))

    def key_proc(self, key):
        if len(key) == 1:
            if key.lower() == 'w' and self._esPile is not None and len(self._lines) > 1:
                self._stopSurt()
                i = self._esPile.focus_position
                if i == len(self._lines) - 1:
                    self._lines[i], self._lines[i - 1] = self._lines[i - 1], self._lines[i]
                else:
                    self._lines[i], self._lines[i + 1] = self._lines[i + 1], self._lines[i]
                self._showLabels()
            elif key.lower() == 'e' and self._esPile is not None and len(self._lines) > 1:
                self._stopSurt()
                i = self._esPile.focus_position
                l = self._lines.pop(i)
                self._lines.append(l)
                self._showLabels()
            elif key.lower() == 'b' and self._esPile is not None and len(self._lines) > 1:
                self._stopSurt()
                i = self._esPile.focus_position
                l = self._lines.pop(i)
                self._lines.insert(0, l)
                self._showLabels()
        elif key == "surf":
            self._footer.set_text("surf")
            self._updateConsole()

if __name__ == "__main__":
    pass
