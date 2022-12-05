# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     objelf
   Description :
   Author :       liaozhaoyan
   date：          2022/11/5
-------------------------------------------------
   Change Activity:
                   2022/11/5:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import datetime
import os
import sys
import shlex
import time
import json
import gc
import re
from subprocess import PIPE, Popen
from threading import Thread, Lock
from atobj import CatObj
from dict2db import Cobj2db


class Cobj2json(object):
    reCellHead = re.compile(r"\<\d+\>\<[0-9a-f]+\>\:")
    reInParenthesis = re.compile(r"(?<=\()[^\(\)]+(?=\))")

    def __init__(self):
        super(Cobj2json, self).__init__()
        self._atObj = CatObj()
        self._getStr = None

    def _compileUnitHead(self, lines):
        while True:
            for i, line in enumerate(lines[:-1]):
                if line.startswith("Contents of the") and not line.startswith("Contents of the .debug_info section:"):
                    return 0, None
                if Cobj2json.reCellHead.search(line):
                    return 1, lines[i:]
            tail = lines[-1]
            s = tail + self._getStr()
            lines = s.split("\n")

    def _compileUnitEnd(self, lines):
        res = []
        while True:
            for i, line in enumerate(lines[:-1]):
                line = line.lstrip()
                if len(line):
                    if line[0] == "<":
                        res.append(line)
                    else:
                        return res, lines[i:]
            tail = lines[-1]
            s = tail + self._getStr()
            lines = s.split("\n")

    def _findHead(self):
        tail = ""
        while True:
            s = tail + self._getStr()
            lines = s.split("\n")
            for i, line in enumerate(lines[:-1]):
                if line.startswith("Contents of the .debug_info section:"):
                    return lines[i:]
            tail = lines[-1]

    def _parseLine(self, line):
        if Cobj2json.reCellHead.search(line):
            head, content = line.split(":", 1)
            levels, offsets = head.split("><")
            level = int(levels[1:], 10)
            offset = int(offsets[:-1], 16)
            tag = "tag_name"
            fit = Cobj2json.reInParenthesis.findall(content)
            if len(fit):
                value = fit[0]
            else:
                value = None
        else:
            level = -1
            head, content = line.split(">", 1)
            offset = int(head[1:], 16)
            tags, values = content.split(":", 1)
            tag = tags.strip()
            if tag in self._atObj.atDict:
                values = values.lstrip()
                value = self._atObj.parse(tag, values)
            elif tag == "Unknown AT value":
                tag = None
                value = ""
            else:
                print("\t tag: %s not in at dict. value: %s", tag, values)
                value = values.strip()
        return level, offset, tag, value

    def _decode(self, lines):
        lastLevel = 0
        dStack = []
        dRet = {}
        for i, line in enumerate(lines):
            level, offset, tag, value = self._parseLine(line)
            if tag is None:     # for Unknown AT value
                continue
            if level >= 0:
                if value is None:
                    continue
                dRet = {tag: value, "offset": offset}
                if level == lastLevel:
                    if level == 0:
                        dStack.append(dRet)
                    else:
                        dParent = dStack[level - 1]
                        dRet = {tag: value, "offset": offset}
                        if "child" not in dParent:
                            raise ValueError("should add child.")
                        else:
                            dParent['child'].append(dRet)
                        dStack[level] = dRet
                elif level > lastLevel:     # > need add child.
                    if level > lastLevel + 1:
                        print("pid %d" % os.getpid())
                        raise ValueError("level %d, lastLevel %d" % (level, lastLevel))
                    dParent = dStack[level - 1]
                    if "child" in dParent:
                        raise ValueError("should no child.")
                    dParent['child'] = [dRet]
                    dStack.append(dRet)
                    lastLevel = level
                elif level < lastLevel:     # back to last level
                    dParent = dStack[level - 1]
                    dParent['child'].append(dRet)
                    dStack = dStack[:level+1]
                    dStack[level] = dRet
                    lastLevel = level
            else:  # single line.
                dRet[tag] = value
        return dStack[0]

    def accept(self, getStr):
        self._getStr = getStr
        tail = self._findHead()
        flag, tail = self._compileUnitHead(tail)
        while flag:
            lines, tail = self._compileUnitEnd(tail)
            # with open("cell.txt", "w") as f:
            #     f.write("\n".join(lines))
            yield self._decode(lines)
            flag, tail = self._compileUnitHead(tail)


class Ctest(object):
    def __init__(self, path="/root/1ext/code/surftrace/tools/dwarf/walks/samelf/dwarf.txt"):
        super(Ctest, self).__init__()
        self._handle = open(path, 'r')
        self._db = Cobj2db("elf", "info.db")

    def read(self):
        res = self._handle.read(1024)
        if res == "":
            raise OSError("end of file")
        return res

    def test(self):
        o = Cobj2json()
        ana = o.accept(self.read)
        for res in ana:
            self._db.walks(res)
            del res
            gc.collect()


class CmonThread(Thread):
    def __init__(self, mon):
        super(CmonThread, self).__init__()
        self.daemon = True
        self._mon = mon
        self.start()

    def run(self):
        while True:
            time.sleep(0.1)
            if self._mon.poll() is not None:
                self._mon.closePipe()
                break


class CobjElf(object):
    def __init__(self, elf):
        super(CobjElf, self).__init__()
        if not os.path.exists(elf) or not os.path.isfile(elf):
            raise ValueError("%s is not a file" % elf)

        self._l = Lock()
        self._r, self._w = -1, -1
        self._elf = elf
        self._p = None

    def __del__(self):
        if hasattr(self, "_p"):
            self.closePipe()

    def _exec(self):
        cmd = "readelf -w %s" % self._elf
        with self._l:
            self._r, self._w = os.pipe()
            self._p = Popen(shlex.split(cmd), stdout=self._w)
        return self._p

    def poll(self):
        res = 0
        with self._l:
            if hasattr(self, "_p"):
                res = self._p.poll()
        return res

    def closePipe(self):
        with self._l:
            if self._r >= 0:
                os.close(self._r)
                os.close(self._w)
                self._r = -1
                self._w = -1
                try:
                    self._p.terminate()
                except OSError:
                    pass
                del self._p

    def _read(self, size=16384):
        if sys.version_info.major == 2:
            res = os.read(self._r, size)
        else:
            res = os.read(self._r, size).decode()
        if res is None or res == "":
            raise OSError("end of file.")
        return res

    def out(self, toFile):
        self._exec()
        with open(toFile, 'w') as f:
            while True:
                try:
                    s = self._read()
                except OSError:
                    break
                f.write(s)

    def toDb(self, name, db):
        o = Cobj2json()
        self._exec()
        t = CmonThread(self)
        ana = o.accept(self._read)
        for res in ana:
            obj = Cobj2db(name, db)
            # with open("vm.json", "w") as f:
            #     json.dump(res, f)
            obj.walks(res)
        self.closePipe()
        t.join(0.1)


if __name__ == "__main__":
    e = CobjElf("/home/lbc/.output/lbc.bpf.o")
    # e.out("vm.db")
    t1 = datetime.datetime.now()
    e.toDb("bpf", "bpf.db")
    print("to Db.", datetime.datetime.now() - t1)
    # t = Ctest()
    # t = Ctest("./vm.txt")
    # t.test()
    pass
