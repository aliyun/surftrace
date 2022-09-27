# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     fxpr
   Description :
   Author :       liaozhaoyan
   date：          2022/3/20
-------------------------------------------------
   Change Activity:
                   2022/3/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import re
from .regSplit import probeReserveVars, isStruct, stripPoint, regIndex, transReg, splitExpr
from .surfException import ExprException, DbException


class Cfxpr(object):
    def __init__(self, parser, arch):
        super(Cfxpr, self).__init__()
        self._parser = parser
        self._arch = arch
        self._setupRe()

    def _setupRe(self):
        self._reSurfComm = re.compile(r"[a-zA-z][a-zA-z0-9_]*=\$comm")
        self._reSurfProbe = re.compile(
            r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)(%|@|\$stack)")
        self._reSurfRet = re.compile(
            r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)(\$retval|\$stack|@|%)")
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
        self._res = {}

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
        size = 1536  # for skb_buff
        try:
            res = self._parser.getStruct(stripPoint(sStruct))
        except DbException as e:
            raise ExprException('db get %s return %s' % (sStruct, e.message))
        if res['log'] != "ok.":
            raise DbException('db get %s return %s' % (sStruct, res['log']))
        if 'res' in res and res['res'] is not None and res['res']['name'] in self._netStructs:
            offset = res['res']['size']
            for k, v in self._netDatas.items():
                name = "%s[%d]" % (k, size / v[0])
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
            raise ExprException(
                "argi num %d, which is larger than func args number %d." % (argi, len(self._func['args'])))

        if types == '':
            t = self._res['type']
            if argMode != "mReg":
                argt = ''
            elif inFlag:  # check mReg condition.
                argt = 'u64'
            elif t in ('p', 'P'):
                argt = self._func['args'][argi]
            elif t in ('r', "R"):
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
        elif (sType == "char" or " char" in sType) and '[' in lastCell['name']:
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
        # layer 2
        if sStruct == 'struct ethhdr':
            if layer != 2:
                raise ExprException("can not get ethhdr at layer%d" % layer)
            off += self.showMemberOffset(member, sStruct)
            self._fxprAddPoint(off)
            return
        if layer == 2:
            off += self.showTypeSize('struct ethhdr')
        # layer 3
        if sStruct == 'struct iphdr':
            if layer > 3:
                raise ExprException("can not get iphdr at layer%d" % layer)
            off += self.showMemberOffset(member, sStruct)
            self._fxprAddPoint(off)
            return
        if layer < 4:
            off += self.showTypeSize('struct iphdr')
        # layer 4
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
        sym, sType, v = s[0], None, s
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
            elif res['type'] != "struct":  # not nested structs mode, if in nested, then clear.
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

    def expr(self, func, inFlag, symbol, res):
        cmd = ""
        try:
            self._func = self._getVmFunc(func)['res'][0]
        except (TypeError, KeyError, IndexError):
            raise DbException("no %s debuginfo  in file." % symbol)

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
        return cmd


if __name__ == "__main__":
    pass
