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
from .regSplit import probeReserveVars, isStruct, stripPoint, regIndex, transReg, spiltInputLine, splitExpr
from .dbParser import CdbParser
from .lbcClient import ClbcClient
from .gdbParser import CgdbParser


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

        self._arch = arch
        if self._arch == "":
            self._arch = self._getArchitecture()
        self._args = args
        self._stack = stack
        if isinstance(args, list):
            self._reSurfComm = re.compile(r"[a-zA-z][a-zA-z0-9_]*=\$comm")
            self._reSurfProbe = re.compile(r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)(%|@|\$stack)")
            self._reSurfRet = re.compile(r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)(\$retval|\$stack|@|%)")
            self._reLayer = re.compile(r"l[234]")
            self._reBrackets = re.compile(r"(?<=\().+?(?=\))")
            self._reSquareBrackets = re.compile(r"(?<=\[).+?(?=\])")
            self._netStructs = ('struct ethhdr', 'struct iphdr', 'struct icmphdr', 'struct tcphdr', 'struct udphdr')
            self._netDatas = {'cdata': (1, "unsigned char"),
                              'sdata': (2, "unsigned short"),
                              'ldata': (4, "unsigned int"),
                              'qdata': (8, "unsigned long"),
                              'Sdata': (1, "char"),
                              }
            self._strFxpr = ""
            self.__format = 'u'
            self._func = None
            self._argSym = ""
            self._kp_events = None

        self._cb = cb
        if cbOrig is not None:
            self._cbOrig = cbOrig

        if cbShow:
            self._cbShow = cbShow
        else:
            self._cbShow = self._showFxpr
        self._fullWarning = True

    def _getArchitecture(self):
        return self._c.cmd('uname -m').strip()

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
        beg = 0; ret = ""
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

    def __setupEvent(self, res):
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

    def _memINStruct(self, mem, tStruct):
        if tStruct is None:
            return None
        arrMem = False
        if '[' in mem:
            mem = mem.split('[', 1)[0]
            arrMem = True
        for cell in tStruct["res"]["cell"]:
            name = cell['name']
            if arrMem:
                if '[' not in name:
                    continue
            if '[' in name:
                name = name.split('[', 1)[0]
            if name == mem:
                return cell
            elif not arrMem and name.startswith(mem + "."):
                return {"type": "struct"}
        return None

    def __checkFormat(self, e):
        _, flag = e.split("=")
        self.__format = 'u'
        if flag[0] in "SUX":
            self.__format = str.lower(flag[0])

    def __checkSurfComm(self, e):
        return self._reSurfComm.match(e)

    def __checkBegExpr(self, e):
        if self._res['type'] == 'p':
            res = self._reSurfProbe.match(e)
        else:
            res = self._reSurfRet.match(e)
        if res is None:
            raise ExprException("error in expr %s." % e)
        return res
    
    def _splitXpr(self, xpr):
        for i, c in enumerate(xpr):
            if c == '.' or (c == '-' and xpr[i + 1] == '>'):
                return xpr[:i], xpr[i:]
        return xpr, ''
    
    def __checkVar(self, var):
        if var in probeReserveVars:
            raise ExprException('%s is reserve word, can not used for args' % var)

    def __checkSkbStruct(self, sStrcut):
        if sStrcut.strip("* ") not in self._netStructs:
            raise ExprException("type: %s is no not a legal struct." % sStrcut)
    
    def __filtType(self, s):
        try:
            return self._reBrackets.findall(s)[0]
        except (TypeError, IndexError):
            raise ExprException("%s may not match" % s)

    def __netParse(self, sType, pr):
        self.__checkSkbStruct(sType)
        if self._reLayer.match(pr):
            pr = pr[2:]
        return pr
    
    def showTypeSize(self, sType):
        multi = 1
        if "[" in sType:
            sType, multi = sType.split("[", 1)
            multi = int(multi[:-1])
        if '*' in sType:
            sType = "_"
        if isStruct(sType):
            dRes = self._getVmStruct(sType)
        else:
            dRes = self._getVmType(sType)
        return multi * dRes['res']['size']

    def showMemberOffset(self, member, structName):
        add = 0
        if '[' in structName:
            structName = structName.split('[')[0].strip()

        if '[' in member:
            add = int(self._reSquareBrackets.findall(member)[0])
            member = member.split('[')[0]
        structName = structName.replace("*", "").strip()
        dRes = self._getVmStruct(structName)
        for cell in dRes['res']['cell']:
            name = cell['name']
            indexMax = 0
            if '[' in name:
                try:
                    indexMax = int(self._reSquareBrackets.findall(name)[0])
                except IndexError:
                    indexMax = -1
                except ValueError:
                    raise ExprException("struct %s member %s array index error." % (structName, name))
                name = name.split("[")[0]
            if name == member:
                if add > 0:
                    if 0 < indexMax <= add:
                        raise ExprException("member %s max index is %d, input %d, overflow" % (name, indexMax, add))
                    add *= int(cell['size'] / indexMax)
                return cell['offset'] + add
        raise ExprException("there is not member named %s in %s" % (member, structName))

    def _getVmStruct(self, sStruct):
        size = 1536   # for skb_buff
        try:
            res = self._parser.getStruct(stripPoint(sStruct))
        except DbException as e:
            raise ExprException('db get %s return %s' % (sStruct, e.message))
        if res['log'] != "ok.":
            raise DbException('db get %s return %s' % (sStruct, res['log']))
        if 'res' in res and res['res'] is not None and res['res']['name'] in self._netStructs:
            offset = res['res']['size']
            for k, v in self._netDatas.items():
                name = "%s[%d]" % (k, size/v[0])
                cell = {"type": v[1], 'offset': offset, "size": size, "bits": "", "name": name}
                res['res']['cell'].append(cell)
        return res

    def _getVmType(self, sType):
        try:
            res = self._parser.getType(sType)
        except DbException as e:
            raise ExprException('db get %s return %s' % (sType, e.message))
        if res['log'] != "ok.":
            raise DbException('db get %s return %s' % (sType, res['log']))
        return res
    
    def _getVmFunc(self, func):
        try:
            res = self._parser.getFunc(func)
        except DbException as e:
            raise ExprException('db get %s return %s' % (func, e.message))
        if res['log'] != "ok.":
            raise DbException('db get %s return %s' % (func, res['log']))
        return res

    def __getExprArgi(self, e, inFlag=False):
        # expression: a=@(struct iphdr *)l4%1->saddr uesrs=!(struct task_struct *)%0->mm->mm_users
        # e is already checked at self.__checkBegExpr
        argModeD = {'%': "mReg", '@': "mAddr", "$": "mVar"}
        var, expr = e.split("=", 1)
        self.__checkVar(var)

        showType = ''
        if expr[0] in ('S', 'U', 'X'):
            expr = expr[1:]
            showType = expr[0]

        argMode = "None"
        if '(' in expr:
            _, sMode = expr.rsplit('(', 1)
        else:
            sMode = expr
        for k in argModeD.keys():
            if k in sMode:
                self._argSym = k
                argMode = argModeD[k]
                types, xpr = expr.rsplit(k, 1)
        if argMode not in argModeD.values():
            raise ExprException("bad arg mode for expr %s, mode: %s" % (expr, argMode))

        reg, xpr = self._splitXpr(xpr)
        if argMode == 'mReg':
            if reg.isdigit():
                argi = int(reg)
            else:
                argi = regIndex(reg, self._arch)
            regArch = transReg(argi, self._arch)
        else:
            argi = 0
            regArch = reg

        if not inFlag and argi > len(self._func['args']):
            raise ExprException("argi num %d, which is larger than func args number %d." % (argi, len(self._func['args'])))

        if types == '':
            if argMode != "mReg":
                argt = ''
            elif inFlag:   # check mReg condition.
                argt = 'u64'
            elif self._res['type'] == 'p':
                argt = self._func['args'][argi]
            elif self._res['type'] == 'r':
                argt = self._func['ret']
            else:
                raise ExprException("can not get arg type for %s" % expr)
        else:
            argt = types
        return showType, regArch, argt, xpr
    
    def _splitPr(self, argt, prs):
        cells = []
        beg = 0
        for i, c in enumerate(prs):
            if c == ".":
                cells.append(prs[beg:i])
                cells.append(".")
                beg = i + 1
            elif c == '-':
                if prs[i + 1] != '>':
                    raise ExprException("bad point mode, should be '->'")
                cells.append(prs[beg:i])
                cells.append("->")
                beg = i + 2
        if beg < len(prs):
            cells.append(prs[beg:])
        if (len(cells)):
            cells[0] = argt
        else:
            cells.append(argt)
        return cells

    def _cellCheckArray(self, sMem, res):
        name = res['name']
        if res['type'] == "char":
            return
        if '[' in name:
            if '[' not in sMem:
                raise ExprException("member %s is an array, should add [, member is %s" % (name, sMem))
            try:
                iMem = self._reSquareBrackets.findall(sMem)[0]
                iName = self._reSquareBrackets.findall(name)[0]
            except TypeError:
                raise ExprException("%s or %s is not in []" % (sMem, name))
            try:
                iMem = int(iMem)
            except ValueError:
                raise ExprException("%s in %s is not int" % (iMem, sMem))
            if iName == "":
                return
            else:
                try:
                    iName = int(iName)
                except ValueError:
                    raise ExprException("remote type %s error" % name)
                if iMem >= iName:
                    raise ExprException("%s max index is %d, you set %d, overflow" % (name, iName, iMem))
    
    def _fxprAddPoint(self, off):
        self._strFxpr = "+0x%x(" % off + self._strFxpr + ')'

    def _fxprAddMem(self, off):
        # +0xa(%di)
        try:
            prev, cmd = self._strFxpr.split("(", 1)
        except:
            raise ExprException("regs should start with ->.")
        last = int(prev[1:], 16)
        self._strFxpr = "+0x%x(" % (off + last) + cmd

    def _fxprAddSuffix(self, lastCell):
        sType = lastCell["type"]
        if "char *" in sType:
            self._strFxpr = "+0x0(%s):string" % self._strFxpr
        elif (sType == "char" or " char" in sType ) and '[' in lastCell['name']:
            self._strFxpr += ":string"
        elif sType == "struct":
            raise ExprException("lastCell type %s, which is incompletely." % lastCell["type"])
        else:
            formDict = {1: 8, 2: 16, 4: 32, 8: 64}
            if 'name' in lastCell:
                name = lastCell['name']
                if "[" in name:
                    res = self._parser.getType(sType)
                    if res['log'] == "ok." and 'res' in res and res['res'] is not None:
                        cell = res['res']
                        size = cell['size']
                    else:
                        raise DbException("get type %s failed" % sType)
                else:
                    size = lastCell['size']
            else:
                res = self._parser.getType(sType)
                if res['log'] == "ok." and 'res' in res and res['res'] is not None:
                    cell = res['res']
                    size = cell['size']
                else:
                    raise DbException("get type %s failed" % sType)
            if size in formDict:
                self._strFxpr += ":%s%d" % (self.__format, formDict[size])
            else:
                raise ExprException(
                    "last cell type: %s, can not show." % (lastCell["type"]))
    
    def _procSkb(self, member, sStruct, layer):
        # struct is already checked in _cellCheck __getCellMem, func
        off = self.showMemberOffset('data', 'struct sk_buff')
        self._fxprAddPoint(off)

        sStruct = stripPoint(sStruct)
        off = 0
        #layer 2
        if sStruct == 'struct ethhdr':
            if layer != 2:
                raise ExprException("can not get ethhdr at layer%d" % layer)
            off += self.showMemberOffset(member, sStruct)
            self._fxprAddPoint(off)
            return
        if layer == 2:
            off += self.showTypeSize('struct ethhdr')
        #layer 3
        if sStruct == 'struct iphdr':
            if layer > 3:
                raise ExprException("can not get iphdr at layer%d" % layer)
            off += self.showMemberOffset(member, sStruct)
            self._fxprAddPoint(off)
            return
        if layer < 4:
            off += self.showTypeSize('struct iphdr')
        #layer 4
        off += self.showMemberOffset(member, sStruct)
        self._fxprAddPoint(off)

    def _procFxpr(self, member, structName, mode):
        first = structName[0]
        orig = structName
        if first in ('(', '!', '@'):
            structName = self.__filtType(structName)
            if first == '@':
                try:
                    match = self._reLayer.search(orig).group(0)
                    layer = int(match[1])
                except AttributeError:
                    layer = 3
                if mode != '->':
                    raise ExprException("net struct process should in -> mode.")
                self._procSkb(member, structName, layer)
                return
        off = self.showMemberOffset(member, structName)
        if mode == '.':
            self._fxprAddMem(off)
        else:
            self._fxprAddPoint(off)

    def __getCellMem(self, s):
        sym = s[0]
        sType = None; v = s
        if sym in ('@', '(', '!'):
            sType = self.__filtType(s)
            _, v = s.split(')')
            if sym == '@':
                v = self.__netParse(sType, v)
        return sType, v
    
    def _cellCheck(self, cells, reg, getCell=False):
        self._strFxpr = self._argSym + reg
        if cells[0] == '':
            return {"type": ''}

        i, end, lastCell = 0, len(cells), None
        sMem, origType, sType, tStruct, origMode = "", "unkown", "unkown", None, '->'

        if end <= 2:
            sType = cells[0]
            if '(' in sType:
                lastCell = {"type": self.__filtType(sType)}
            else:
                lastCell = {"type": sType}
        while i + 2 < end:
            if sMem == "":
                origType = sType = cells[i]
                sMode = cells[i + 1]
                tMem, sMem = self.__getCellMem(cells[i + 2])
                if sType[0] in ('(', '@', '!'):
                    sType = self.__filtType(sType)
                if sMode == ".":
                    if sType.endswith("*"):
                        raise ExprException("%s is a point, should use '->' to get member" % sType)
                elif sMode == "->":
                    if not sType.endswith("*"):
                        raise ExprException("%s is a type, should use '.' to get member" % sType)
                origMode = sMode
                sType = isStruct(sType)
                if sType is None:
                    raise ExprException("%s is not a legal struct types." % sType)
                tStruct = self._getVmStruct(sType)
                if tStruct['res'] is None:
                    raise ExprException("%s is not a valid struct in database." % sType)
            else:
                sMode = cells[i + 1]
                if sMode != ".":
                    ExprException("%s:nested structure members should be '.' mode, %s" % (sType, sMem))
                tMem, v = self.__getCellMem(cells[i + 2])
                sMem = "%s.%s" % (sMem, v)
            lastCell = res = self._memINStruct(sMem, tStruct)
            if res is None:
                raise ExprException("%s is not a member in %s" % (sMem, sType))
            elif res['type'] != "struct":   # not nested structs mode, if in nested, then clear.
                self._cellCheckArray(sMem, res)
                self._procFxpr(sMem, origType, origMode)
                sMem = ""
            if tMem is None:
                cells[i + 2] = res['type']
            else:
                cells[i + 2] = tMem
                lastCell = {"type": tMem}
            i += 2
        if not getCell:
            self._fxprAddSuffix(lastCell)
        return lastCell

    def _checkExpr(self, e, inFlag):
        res = self.__checkSurfComm(e)
        if res:
            self._strFxpr = "$comm"
            return {"type": "$comm"}

        self.__checkBegExpr(e)
        self.__checkFormat(e)

        showType, reg, argt, xpr = self.__getExprArgi(e, inFlag)

        cells = self._splitPr(argt, xpr)
        res = self._cellCheck(cells, reg)
        if res['type'] == "struct":
            raise ExprException("last member is nested struct type, which is not completed.")
        return res

    def __checkSymbol(self, symbol):
        offset = None
        if '+' in symbol:
            func, offset = symbol.split('+', 1)
        else:
            func = symbol
        if not self._show:
            func = self._checkAvailable(func)
            if func is None:
                raise InvalidArgsException("%s is not in available_filter_functions" % func)
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
        if res['type'] == 'e':
            self.__setupEvent(res)
            return

        name = "f%d" % i
        cmd = "%s:f%d " % (res['type'], i)
        symbol = res['symbol']
        inFlag = False

        func = symbol
        if "+" in func:
            func = func.split("+", 1)[0]
            inFlag = True
        try:
            self._func = self._getVmFunc(func)['res'][0]
        except (TypeError, KeyError, IndexError):
            raise DbException("no %s debuginfo  in file." % symbol)
        cmd += self.__checkSymbol(symbol)

        vars = []
        for expr in splitExpr(res['args']):
            if expr == "":
                continue
            self._res = res
            self._checkExpr(expr, inFlag)
            var, _ = expr.split("=", 1)
            if var in vars:
                raise ExprException("var %s is already used at previous expression" % var)
            vars.append(var)
            cmd += " %s=" % var + self._strFxpr
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
            elif res.startswith("%s.isra" % name):
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
