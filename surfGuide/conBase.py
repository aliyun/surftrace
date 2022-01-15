# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     conBase
   Description :
   Author :       liaozhaoyan
   date：          2021/12/10
-------------------------------------------------
   Change Activity:
                   2021/12/10:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
from datetime import datetime
import re

def log(s):
    pass
    with open("opera.log", 'a') as f:
        f.write("%s:" % str(datetime.now()) + s + "\n")

class CfocusPile(urwid.Pile):
    def __init__(self, widget_list, focus_item=None, cb_focus_change=None):
        self._lastFocus = 0
        self._cb_focus = cb_focus_change
        super(CfocusPile, self).__init__(widget_list, focus_item)
        self._lastFocus = self.focus_position

    def _checkFocus(self):
        if self._lastFocus != self.focus_position:
            if self._cb_focus is not None:
                self._cb_focus(self._lastFocus, self.focus_position)
            self._lastFocus = self.focus_position

    def set_focus(self, item):
        super(CfocusPile, self).set_focus(item=item)
        self._checkFocus()

    def keypress(self, size, key):
        ret = super(CfocusPile, self).keypress(size, key)
        self._checkFocus()
        return ret

class CconBase(object):
    palette = [
        ('body', 'white', 'black', 'standout'),
        ('header', 'white', 'dark red', 'bold'),
        ('footer', 'white', 'dark blue', 'bold'),
        ('flagged', 'black', 'dark green', ('bold', 'underline')),
        ('focus', 'light gray', 'dark blue', 'standout'),
        ('flagged focus', 'yellow', 'dark cyan', ('bold', 'standout', 'underline')),
        ('buttn', 'black', 'dark cyan'),
        ('buttnf', 'white', 'dark blue', 'bold'),
        ('edit', 'light gray', 'dark blue'),
        ('chars', 'light gray', 'black'),
        ('exit', 'white', 'dark cyan'),
        ('key', 'light cyan', 'black', 'underline'),
        ('title', 'white', 'black', 'bold'),
        ('dirmark', 'black', 'dark cyan', 'bold'),
        ('flag', 'dark gray', 'light gray'),
        ('error', 'dark red', 'light gray'),
    ]
    _loop = None
    _client = None
    _cb_key = None
    shortCtrlBan = "oydcuvrqtszw?\\"
    shortCtrls = {}
    shortKeys = {}

    _reShortkey  = re.compile(r"(?<=\().+?(?=\))")
    _reShortCtrl = re.compile(r"(?<=\[).+?(?=\])")
    def __init__(self):
        CconBase._cb_key = self.key_proc
        super(CconBase, self).__init__()

        self._shortKeys = {}
        self._shortCtrls = {}

        self.view = self.setupView()
        self.setupKeys()

    def setupKeys(self):
        CconBase.shortKeys = self._shortKeys
        CconBase.shortCtrls = self._shortCtrls

    def setupView(self):
        return None

    def dbGetFun(self, func):
        return self._client.getFunc(func)

    def dbGetStruct(self, sStruct):
        return self._client.getStruct(sStruct)

    def dbGetType(self, sType):
        return self._client.getType(sType)

    def setupDb(self, client):
        CconBase._client = client

    def _create_edit(self, label, text, cb=None):
        w = urwid.Edit(label, text)
        if cb:
            urwid.connect_signal(w, 'change', cb)
        w = urwid.AttrWrap(w, 'edit')
        return w

    def _checkShortcut(self, label, fn, w):
        shortKey = CconBase._reShortkey.search(label)
        if shortKey and len(shortKey.group()) == 1:
            key = shortKey.group()
            self._regShortcut(key, fn, (w,))
            return

        shortCtrl = CconBase._reShortCtrl.search(label)
        if shortCtrl and len(shortCtrl.group()) == 1:
            key = shortCtrl.group()
            self._regShortCtrl(key, fn, (w,))
            return

    def _create_button(self, label, fn, shortcut=None, shortCtrl=None):
        w = urwid.Button(label)
        urwid.connect_signal(w, 'click', fn)
        if shortcut:
            self._regShortcut(shortcut, fn, (w,))
        if shortCtrl:
            self._regShortCtrl(shortCtrl, fn, (w,))
        self._checkShortcut(label, fn, (w,))
        w = urwid.AttrWrap(w, 'buttn', 'buttnf')
        return w

    def _cb_radio_set(self, widget):
        widget.set_state(True)

    def __create_radio(self, grp, label, sel, cb=None):
        if sel < 0:
            res = urwid.RadioButton(grp, label, state=False, on_state_change=cb)
        else:
            res = urwid.RadioButton(grp, label, on_state_change=cb)
        self._checkShortcut(label, self._cb_radio_set, res)
        return res

    def _create_radios(self, rbList, sel=0, vertical=True, cb=None, cb_focus=None):
        radioGroup = []
        typeList = [urwid.AttrWrap(self.__create_radio(radioGroup, txt, sel, cb), 'buttn', 'buttnf') for txt in rbList]
        if sel >= 0:
            radioGroup[sel].set_state(True)
        if vertical:
            if cb_focus:
                radioWids = CfocusPile(typeList, cb_focus_change=cb_focus)
            else:
                radioWids = urwid.Pile(typeList)
        else:
            radioWids = urwid.Columns(typeList)
        return radioWids, radioGroup

    def _cb_check_set(self, widget):
        widget.set_state(True)

    def _create_check(self, label, cb=None):
        res = urwid.CheckBox(label, on_state_change=cb)
        self._checkShortcut(label, self._cb_check_set, res)
        return res

    def _create_checks(self, ckList, vertical=True, cb=None, cb_focus=None):
        checkGroup = []
        wids = []
        for txt in ckList:
            w = self._create_check(txt, cb)
            checkGroup.append(w)
            wids.append(urwid.AttrWrap(w, 'buttn', 'buttnf'))
        if vertical:
            checkWids = CfocusPile(wids, cb_focus_change=cb_focus)
        else:
            checkWids = urwid.Columns(wids, cb_focus_change=cb_focus)
        return checkWids, checkGroup


    def _getRadioSelect(self, radioGroup):
        for index, radio in enumerate(radioGroup):
            if radio.state:
                return index
        return -1

    def _setupHeadFoot(self, head, foot):
        header = urwid.Text(head)
        self._header = urwid.AttrWrap(header, 'header')
        footer = urwid.Text(foot)
        self._footer = urwid.AttrWrap(footer, 'footer')

    def _setupFrame(self, widList, focus=None):
        w = urwid.ListBox(urwid.SimpleListWalker(widList))
        if focus is not None:
            w.set_focus(focus)
        # Frame
        w = urwid.AttrWrap(w, 'body')
        return urwid.Frame(w, self._header, self._footer)

    def _setupTree(self, treeList):
        listBox = urwid.TreeListBox(urwid.TreeWalker(treeList))
        listBox.offset_rows = 1
        w = urwid.AttrWrap(listBox, 'body')
        return urwid.Frame(w, self._header, self._footer)

    def switch_widget(self, obj):
        CconBase._loop.widget = obj.view
        CconBase._cb_key = obj.key_proc
        obj.setupKeys()

    def fresh(self):
        self._shortKeys.clear()
        self._shortCtrls.clear()

        self.view = self.setupView()
        CconBase._loop.widget = self.view

    def redraw(self):
        self._loop.draw_screen()

    def _regShortcut(self, k, cb, args=None, sendKey=False):
        if type(k) != str and len(k) != 1:
            raise ValueError("key: %s is not a valid value for short cut")
        k = k.lower()
        if k in self._shortKeys:
            raise ValueError("shortcut key Ctrl %s is already used by this window, function is %s." % (k, str(CconBase.shortKeys[k])))
        self._shortKeys[k] = [cb, args, sendKey]

    def _regShortCtrl(self, k, cb, args=None, sendKey=False):
        if type(k) != str and len(k) != 1:
            raise ValueError("key: %s is not a valid value for short cut")
        k = k.lower()
        if k in CconBase.shortCtrlBan:
            raise ValueError("shortcut key Ctrl %s is already used by terminal." % k)
        if k in self._shortCtrls:
            raise ValueError("shortcut key Ctrl %s is already used by this window, function is %s." % (k, str(CconBase.shortKeys[k])))
        self._shortCtrls[k] = [cb, args, sendKey]

    def _unregShortcut(self, k):
        if k in self._shortKeys:
            del self._shortKeys[k]

    def _unregShortCtrl(self, k):
        if k in self._shortCtrls:
            del self._shortCtrls[k]

    def __procShortcut(self, procDict, k):
        func, args, sendKey = procDict[k]
        if sendKey: func(k)
        elif args: func(*args)
        else: func()

    def exit(self):
        raise urwid.ExitMainLoop()

    def unhandled_input(self, key):
        if key == 'f8':
            raise urwid.ExitMainLoop()

        # shortcut proc
        if type(key) is str:
            if key.startswith("ctrl "):
                k = key.split(" ", 1)[1]
                if k in CconBase.shortCtrls:
                    self.__procShortcut(CconBase.shortCtrls, k)
                    return
            elif len(key) == 1:
                k = key.lower()
                if k in CconBase.shortKeys:
                    self.__procShortcut(CconBase.shortKeys, k)
                    return

        CconBase._cb_key(key)

    def key_proc(self, key):
        pass

    def loop(self):
        CconBase._loop = urwid.MainLoop(self.view, CconBase.palette, unhandled_input=self.unhandled_input)
        CconBase._cb_key = self.key_proc
        CconBase._loop.run()

if __name__ == "__main__":
    pass
