#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surftrace
   Description :
   Author :       liaozhaoyan
   date：          2021/1/4
-------------------------------------------------
   Change Activity:
                   2021/1/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
import sys
import os
import argparse
import traceback

from .surfException import *
from .headTrans import headTrans, invHeadTrans
from .ftrace import ftrace, save2File, cmdStrings
from .regSplit import spiltInputLine
from .dbParser import CdbParser
from .lbcClient import ClbcClient
from .gdbParser import CgdbParser
from .fxpr import Cfxpr


class surftrace(ftrace):
    def __init__(self, args, parser,
                 show=False, echo=True, arch="", stack=False,
                 cb=None, cbOrig=None, cbShow=None,
                 instance="surftrace"):
        super(surftrace, self).__init__(show=show, echo=echo, instance=instance)
        self._parser = parser
        self._probes = []
        self._events = []
        self._options = []

        self._arch = self._setupArch(arch)

        self._args = args
        self._stack = stack

        if isinstance(args, list):
            self._fxpr = Cfxpr(parser, self._arch)
            self._kp_events = None

        self._cb = cb
        if cbOrig is not None:
            self._cbOrig = cbOrig

        if cbShow:
            self._cbShow = cbShow
        else:
            self._cbShow = self._showFxpr
        self._fullWarning = True
        self._funcs = {
            'e': self._setupEvent,
            'p': self._setupKprobe,
            'r': self._setupKprobe,
            'P': self._setupUprobe,
            'R': self._setupUprobe,
        }

    def _setupArch(self, arch):
        if arch == "":
            return self._c.cmd('uname -m').strip()
        return arch

    def _clearProbes(self):
        if self._show:
            return
        for p in self._probes:
            fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/" % self._instance \
                    + p + "/enable"
            self._echoPath(fPath, "0")
            cmd = '-:%s' % p
            self._echoDPath(self.baseDir + "/tracing/kprobe_events", cmd)
        self._probes = []
        for ePath in self._events:
            fFilter = os.path.join(ePath, "filter")
            self._echoPath(fFilter, '0')
            fPath = os.path.join(ePath, "enable")
            self._echoPath(fPath, "0")
        for op in self._options:
            path, v = op[0], op[1]
            self._echoPath(path, v)
        self._events = []

    def __transFilter(self, filter, i, beg):
        decisions = ('==', '!=', '~', '>=', '<=', '>', '<')
        s = filter[beg:i]
        for d in decisions:
            if d in s:
                k, v = s.split(d)
                if '_' in k:
                    k, v = invHeadTrans(k, v)
                return "%s%s%s" % (k, d, v)
        raise InvalidArgsException("bad filter format %s" % s)

    def __checkFilter(self, filter):
        cpStr = "()|&"
        beg, ret, l = 0, "", len(filter)
        l = len(filter)
        for i in range(l):
            if filter[i] in cpStr:
                if i and beg != i:
                    ret += self.__transFilter(filter, i, beg)
                beg = i + 1
                ret += filter[i]
        if beg != l:
            ret += self.__transFilter(filter, l, beg)
        return ret

    def _showFxpr(self, res):
        print(res)

    def __showExpression(self, sType, fxpr, filter=""):
        res = {"type": sType, "fxpr": fxpr, "filter": filter}
        self._cbShow(res)

    def _setupEvent(self, i, res):
        e = res['symbol']
        eBase = os.path.join(self.baseDir, "tracing/instances/%s/events" % self._instance)
        eDir = os.path.join(eBase, e)
        if not os.path.exists(eDir):
            raise InvalidArgsException("event %s is not an available event, see %s" % (e, eBase))
        if res['filter'] != "":
            filter = res['filter']
            try:
                filter = self.__checkFilter(filter)
            except Exception as e:
                if self._echo:
                    print(e)
                raise InvalidArgsException('bad filter：%s' % filter)
            if self._show:
                self.__showExpression('e', e, filter)
                return
            else:
                fPath = os.path.join(eDir, 'filter')
                self._echoFilter(fPath, "'" + filter + "'")
        if self._show:
            self.__showExpression('e', e)
            return
        else:
            ePath = os.path.join(eDir, 'enable')
            self._echoPath(ePath, "1")
            self._events.append(eDir)

    def __checkSymbol(self, symbol):
        offset = None
        if '+' in symbol:
            func, offset = symbol.split('+', 1)
        else:
            func = symbol
        if not self._show:
            func = self._checkAvailable(func)
            if func is None:
                raise InvalidArgsException("%s is not in available_filter_functions" % symbol)
        if offset:
            return "%s+%s" % (func, offset)
        else:
            return func

    def _clearSymbol(self, name):
        if self._kp_events is None:
            self._kp_events = self._c.cmd("cat %s/tracing/kprobe_events" % self.baseDir).split('\n')
        findStr = "p:kprobes/%s " % name
        for ev in self._kp_events:
            if ev.startswith(findStr):
                fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/" % self._instance\
                        + name + "/enable"
                self._echoPath(fPath, "0")
                cmd = '-:%s' % name
                self._echoDPath(self.baseDir + "/tracing/kprobe_events", cmd)

    def __initEvents(self, i, arg):
        arg = arg.strip('\n')
        if len(arg) == 0:
            return
        try:
            res = spiltInputLine(arg)
        except ExprException as e:
            raise ExprException("expression %s error, %s" % (arg, e.message))
        self._funcs[res['type']](i, res)

    def _setupUprobe(self, i, res):
        t = str.lower(res['type'])
        name = "k%d" % i
        cmd = "%s:k%d " % (t, i)
        symbol = res['symbol']
        pass

    def _setupKprobe(self, i, res):
        name = "k%d" % i
        cmd = "%s:k%d " % (res['type'], i)
        symbol = res['symbol']
        inFlag = False

        func = symbol
        if "+" in func:
            func = func.split("+", 1)[0]
            inFlag = True

        cmd += self.__checkSymbol(symbol)
        cmd += self._fxpr.expr(func, inFlag, symbol, res)

        if not self._show:
            self._clearSymbol(name)
            self._echoDPath(self.baseDir + "/tracing/kprobe_events", "'" + cmd + "'")
            self._probes.append(name)
        if res['filter'] != "":
            try:
                filter = self.__checkFilter(res['filter'])
            except Exception as e:
                if self._echo:
                    print(e)
                raise InvalidArgsException('bad filter：%s' % res['filter'])
            if self._show:
                self.__showExpression(res['type'], cmd, filter)
            else:
                fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/%s/filter" %\
                        (self._instance, name)
                self._echoFilter(fPath, "'%s'" % filter)
                fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/" % self._instance + name + "/enable"
                self._echoPath(fPath, "1")
        else:
            if self._show:
                self.__showExpression(res['type'], cmd)
            else:
                fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/" % self._instance + name + "/enable"
                self._echoPath(fPath, "1")

    def _setupStack(self):
        fPath = self.baseDir + "/tracing/instances/%s/options/stacktrace" % self._instance
        if not os.path.exists(fPath):
            fPath = self.baseDir + "/tracing/options/stacktrace"
        if self._stack:
            self._options.append([fPath, "0"])
            self._echoPath(fPath, "1")
        else:
            self._echoPath(fPath, "0")

    def _initEvents(self, args):
        if len(args) < 1:
            raise InvalidArgsException("no args.")
        for i, arg in enumerate(args):
            self.__initEvents(i, arg)
        if self._show:
            return

        self._setupStack()

    def _checkAvailable(self, name):
        cmd = "cat " + self.baseDir + "/tracing/available_filter_functions |grep " + name
        ss = self._c.system(cmd).strip()
        for res in ss.split('\n'):
            if ':' in res:
                res = res.split(":", 1)[1]
            if ' [' in res:  #for ko symbol
                res = res.split(" [", 1)[0]
            if res == name:
                return res
            elif res.startswith("%s.isra" % name) or res.startswith("%s.part" % name):
                return res
        return None

    def _cbLine(self, line):
        print("%s" % line)

    def procLine(self, line):
        res = self._reSkip.search(line)
        if res is not None:
            if self._fullWarning:
                print("warning: The pipe may already be congested.")
                self._fullWarning = False
            return
        ss = line.split(' ')
        o = ' '
        for s in ss:
            if '=' in s:
                head, value = s.split('=', 1)
                if '_' in head:
                    s = headTrans(head, value)
            o += s + ' '
        self._cb(o)

    def _setupEvents(self):
        try:
            self._initEvents(self._args)
        except (InvalidArgsException, ExprException, FileNotEmptyException) as e:
            self._clearProbes()
            del self._parser
            if self._echo:
                print(e.message)
                traceback.print_exc()
                s = ""
            else:
                s = e.message
            raise InvalidArgsException("input error, %s." % s)

    def _splitFxpr(self, fxpr):
        head, xpr = fxpr.split(" ", 1)
        res = {"name": head.split(':', 1)[1]}
        if ' ' in xpr:
            symbol, pr = xpr.split(" ", 1)
        else:
            symbol = xpr
            pr = ""
        if "+" in symbol:
            raise InvalidArgsException("In-segment offsets are not currently supported.")
        func = self._checkAvailable(symbol)
        if func is None:
            raise InvalidArgsException("symbol %s is not in this kernel." % symbol)
        res['func'] = func
        res['fxpr'] = "%s %s" % (head, func)
        if pr != "":
            res['fxpr'] += " %s" % pr
        return res

    def _initFxpr(self, i, res):
        if res['type'] == 'e':
            res['symbol'] = res['fxpr']
            return self.__setupEvent(res)
        resFxpr = self._splitFxpr(res['fxpr'])

        self._echoDPath(self.baseDir + "/tracing/kprobe_events", "'" + resFxpr['fxpr'] + "'")
        self._probes.append(resFxpr['name'])
        if res['filter'] != "":
            fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/%s/filter" % (self._instance, resFxpr['name'])
            self._echoFilter(fPath, "'%s'" % res['filter'])

        fPath = self.baseDir + "/tracing/instances/%s/events/kprobes/" % self._instance\
                + resFxpr['name'] + "/enable"
        self._echoPath(fPath, "1")

    def _setupFxprs(self):
        fxprs = self._args['fxpr']
        for i, res in enumerate(fxprs):
            try:
                self._initFxpr(i, res)
            except (InvalidArgsException, ExprException, FileNotEmptyException) as e:
                self._clearProbes()
                if self._echo:
                    print(e.message)
                    traceback.print_exc()
                s = e.message
                raise InvalidArgsException("input error, %s" % s)
        self._setupStack()

    def start(self):
        if isinstance(self._args, list):
            self._setupEvents()
        elif isinstance(self._args, dict):
            self._setupFxprs()
        else:
            raise InvalidArgsException("input type: %s, is not support." % type(self._args))

        del self._parser
        if not self._show:
            if self._cb is None:
                self._cb = self._cbLine
            super(surftrace, self).start()

    def stop(self):
        self._clearProbes()
        super(surftrace, self).stop()


def setupParser(mode="remote",
                db="",
                remote_ip="pylcc.openanolis.cn",
                gdb="./gdb",
                vmlinux="",
                arch="",
                ver=""):
    if mode not in ("remote", "local", "gdb"):
        raise InvalidArgsException("bad parser mode: %s" % mode)

    if mode == "local":
        return CdbParser(db)
    if mode == "remote":
        return ClbcClient(server=remote_ip, ver=ver, arch=arch)
    elif mode == "gdb":
        gdbPath = gdb
        return CgdbParser(vmlinuxPath=vmlinux, gdb=gdbPath)


examples = """examples:"""


def main():
    parser = argparse.ArgumentParser(
        description="Trace ftrace kprobe events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )
    parser.add_argument('-v', '--vmlinux', type=str, dest='vmlinux', default="", help='set vmlinux path.')
    parser.add_argument('-m', '--mode', type=str, dest='mode', default="remote", help='set arg parser, fro')
    parser.add_argument('-d', '--db', type=str, dest='db', default="", help='set local db path.')
    parser.add_argument('-r', '--rip', type=str, dest='rip', default="pylcc.openanolis.cn",
                        help='set remote server ip, remote mode only.')
    parser.add_argument('-f', '--file', type=str, dest='file', help='set input args path.')
    parser.add_argument('-g', '--gdb', type=str, dest='gdb', default="./gdb", help='set gdb exe file path.')
    parser.add_argument('-F', '--func', type=str, dest='func', help='disasassemble function.')
    parser.add_argument('-o', '--output', type=str, dest='output', help='set output bash file')
    parser.add_argument('-l', '--line', type=str, dest='line', help='get file disasemble info')
    parser.add_argument('-a', '--arch', type=str, dest='arch', help='set architecture.')
    parser.add_argument('-s', '--stack', action="store_true", help="show call stacks.")
    parser.add_argument('-S', '--show', action="store_true", help="only show expressions.")
    parser.add_argument(type=str, nargs='*', dest='traces', help='set trace args.')
    args = parser.parse_args()
    traces = args.traces

    arch = ""
    if args.arch:
        if args.arch not in ('x86', 'x86_64', 'aarch64'):
            raise InvalidArgsException('not support architecture %s' % args.arch)
        arch = args.arch
    if "LBC_SERVER" in os.environ:
         args.rip = os.environ["LBC_SERVER"]
    localParser = setupParser(args.mode, args.db, args.rip, args.gdb, args.vmlinux, arch)

    if args.line:
        localParser.parserLine(args.line)
        sys.exit(0)
    if args.func:
        localParser.disasFun(args.func)
        sys.exit(0)
    if args.file:
        with open(args.file, 'r') as f:
            ts = f.readlines()
            traces += ts
    if args.output:
        global save2File
        save2File = True

    k = surftrace(traces, localParser, show=args.show, arch=arch, stack=args.stack)
    k.start()
    if not args.show:
        k.loop()
    if args.output:
        with open(args.output, 'w') as f:
            f.write(cmdStrings)


if __name__ == "__main__":
    main()
