# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     publish
   Description :
   Author :       liaozhaoyan
   date：          2022/1/12
-------------------------------------------------
   Change Activity:
                   2022/1/12:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import re
import json
import urwid
from threading import Thread
from zlib import decompress, compress, Z_BEST_COMPRESSION
from base64 import b64encode

from .conBase import CconBase, log
sys.path.append("..")
from surftrace import surftrace, setupParser, InvalidArgsException, DbException

class pubThread(Thread):
    def __init__(self, lines, vers, jump, cbProc, cbDone):
        self._run = True
        self._lines = lines
        self._vers = vers
        self._cbProc = cbProc
        self._cbDone = cbDone
        self._jump = jump
        self._seqd = None
        super(pubThread, self).__init__()

    def _cbShow(self, res):
        self._seqd["fxpr"].append(res)

    def run(self):
        seq = ""
        seqd = {"ver": "expr", "cell": self._lines}

        for ver in self._vers:
            if not self._run:
                return
            parser = setupParser(arch=ver['arch'], ver=ver['ver'])
            self._seqd = {"ver": ver['ver'], "arch": ver['arch'], "fxpr": []}
            try:
                surf = surftrace(self._lines, parser, arch=ver['arch'], show=True, echo=False, cbShow=self._cbShow)
                surf.start()
            except InvalidArgsException as e:
                self._cbProc("parse version %s failed, report: %s" % (ver['ver'], e.message))
                if self._jump: continue
                else:
                    self._run = False
                    return
            except DbException as e:
                self._cbProc("parse version %s failed, report %s, may symbol not in this version." % (ver['ver'], e.message))
                if self._jump: continue
                else:
                    self._run = False
                    return
            seq += json.dumps(self._seqd) + "\n"
            self._cbProc("%s pass." % ver['ver'])
        if seq != "":
            seq = json.dumps(seqd) + "\n" + seq
            self._cbDone(seq[:-1])
        self._run = False

    def stop(self):
        self._run = False
        self.join()

    def working(self):
        return self._run

class Cpublish(CconBase):
    def __init__(self, parent, lines, fName, vers):
        self._parent = parent
        self._lines = lines
        self._vers = vers
        self._path = fName.rsplit("/", 1)[0]
        self._reFile = re.compile(r"[\w][\w_]*[\w]")
        self._seq = ""
        self._pub = None
        super(Cpublish, self).__init__()

    def _checkPub(self, fName, w):
        if w.get_label().startswith("sav") and os.path.exists(fName):
            self._footer.set_text("%s is already exist." % fName)
            return False
        return True

    def _saveOrigin(self, fName, t, w):
        fName += ".orig"
        if not self._checkPub(fName, w):
            return
        with open(fName, "w") as f:
            f.write(self._seq)
        self._footer.set_text("%s is saved" % fName)

    def _saveBin(self, fName, t, w):
        fName += ".bin"
        if not self._checkPub(fName, w):
            return
        bin = compress(self._seq, Z_BEST_COMPRESSION)
        with open(fName, "wb") as f:
            f.write(bin)
        self._footer.set_text("%s is saved" % fName)

    def _savePy(self, fName, t, w):
        fName += ".py"
        if not self._checkPub(fName, w):
            return
        bin = compress(self._seq, Z_BEST_COMPRESSION)
        b64 = b64encode(bin)
        model = "../example/pubLoader.py"
        with open(model, "r") as f:
            src = f.read()
        src = src.replace('CpubLoader', 'C%sLoader' % t)
        src = src.replace('pubString = "to_be_replaced."', 'pubString = "%s"' % b64)
        with open(fName, "w") as f:
            f.write(src)
        self._footer.set_text("%s is saved" % fName)

    def _cbPubProc(self, t):
        self._footer.set_text(t)
        self.redraw()

    def _cbPubDone(self, seq):
        self._seq = seq
        self._footer.set_text("publish success full, cease %d version" % (seq.count('\n') - 1))
        self.redraw()

    def _cb_cancel_clk(self, widget):
        if self._pub and self._pub.working():
            return
        self.switch_widget(self._parent)

    def _cb_publish_clk(self, widget):
        if self._pub and self._pub.working():
            return
        self._seq = ""
        self._pub = pubThread(self._lines, self._vers, self._jump.get_state(), self._cbPubProc, self._cbPubDone)
        self._pub.start()

    def _cb_save_clk(self, widget):
        if self._pub and self._pub.working():
            return
        if self._seq == "":
            self._footer.set_text("seq is None, you should publish at first.")
            return
        if not os.path.isdir(self._path):
            self._footer.set_text("path %s is not exist any more." % self._path)
            return
        t = self._eFile.get_edit_text()
        m = self._reFile.search(t)
        if m is None or len(m.group()) != len(t):
            self._footer.set_text("%s is not a regular file name. you can input word and '_', system will add suffix" % (t))
            return

        fName = os.path.join(self._path, t)
        i = self._getRadioSelect(self._radioGrp)
        chooseDitct = {0: self._saveOrigin, 1: self._saveBin, 2: self._savePy}
        chooseDitct[i](fName, t, widget)

    def _cb_file_edit(self, widget, t):
        pass

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("publish in %s." % self._path, "publish %d fxpr, %d versions." % (len(self._lines), len(self._vers)))

        lFile = urwid.AttrWrap(urwid.Text("file name:", align="right"), "body")
        self._eFile = self._create_edit("", "", cb=self._cb_file_edit)
        edits = urwid.Columns([('weight', 1, lFile),
                               ('weight', 4, self._eFile)])

        self._rbList = ["origin", "bin", "single py"]
        self._radioWids, self._radioGrp = self._create_radios(self._rbList)
        label = urwid.AttrWrap(urwid.Text("save file type:", align="right"), "body")
        choose = urwid.Columns([label, self._radioWids, dummy])

        jumpWids, jumps = self._create_checks(["jump on surf failed."])
        jumpLine = urwid.Columns([dummy, dummy, jumpWids])
        self._jump = jumps[0]

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnPub = self._create_button("[p]ublish", self._cb_publish_clk)
        btnForce = self._create_button("[f]orce save", self._cb_save_clk)
        btnSave = self._create_button("sav[e]", self._cb_save_clk)
        btns1 = urwid.Columns([dummy, dummy, dummy, btnPub, dummy])
        btns2 = urwid.Columns([btnCancel, dummy, btnForce, dummy, btnSave])

        frame = self._setupFrame([edits, dummy, choose, dummy, jumpLine, dummy, btns1, btns2])
        return frame

if __name__ == "__main__":
    pass
