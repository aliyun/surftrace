# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     argsGuide
   Description :
   Author :       liaozhaoyan
   date：          2021/12/11
-------------------------------------------------
   Change Activity:
                   2021/12/11:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import urwid
import re
from .conBase import CconBase, log
from .structSelector import CstructSelctor
from .surfExpression import ExprException, stripPoint, splitExpr, isStruct, probeReserveVars, regIndex, transReg
from .lbcClient import DbException
import inspect

class CargsGuide(CconBase):
    def __init__(self, func, parent, res):
        self._func = func
        self._parent = parent
        self._res = res
        super(CargsGuide, self).__init__()
        self._reSurfProbe = re.compile(r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)%")
        self._reSurfRet = re.compile(r"[a-zA-z][a-zA-z0-9_]*=[SUX]?(@\(struct .*\*\)(l[234]|)|\!\(.*\)|)\$retval")
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

    def __checkVar(self, var):
        if var in probeReserveVars:
            raise ExprException('%s is reserve word, can not used for args' % var)

    def __checkSkbStruct(self, sStrcut):
        if sStrcut.strip("* ") not in self._netStructs:
            raise ExprException("type: %s is no not a legal struct." % sStrcut)

    def _splitXpr(self, xpr):
        for i, c in enumerate(xpr):
            if c in ('.', '-'):
                return xpr[:i], xpr[i:]
        return xpr, ''

    def __getExprArgi(self, e):
        # expression: a=@(struct iphdr *)l4%1->saddr uesrs=!(struct task_struct *)%0->mm->mm_users
        # e is already checked at self.__checkBegExpr
        var, expr = e.split("=", 1)
        self.__checkVar(var)

        showType = ''
        if expr[0] in ('S', 'U', 'X'):
            expr = expr[1:]
            showType = expr[0]
        if self._res['type'] == 'p':
            types, xpr = expr.split('%', 1)
            reg, xpr = self._splitXpr(xpr)
            if reg.isdigit():
                argi = int(reg)
            else:
                argi = regIndex(reg)
            if types == '':
                argt = self._func['args'][argi]
            else:
                argt = types
            regArch = transReg(argi)
        else:
            types, xpr = expr.split('$retval')
            if types == '':
                argt = self._func['ret']
            else:
                argt = types
            regArch = '$retval'
        return showType, regArch, argt, xpr

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

    def _getVmStruct(self, sStruct):
        size = 1536   # for skb_buff
        try:
            res = self.dbGetStruct(stripPoint(sStruct))
        except DbException as e:
            raise ExprException('db get %s return %s' % (sStruct, e.message))
        if 'res' in res and res['res'] is not None and res['res']['name'] in self._netStructs:
            offset = res['res']['size']
            for k, v in self._netDatas.items():
                name = "%s[%d]" % (k, size/v[0])
                cell = {"type": v[1], 'offset': offset, "size": size, "bits": "", "name": name}
                res['res']['cell'].append(cell)
        return res

    def _getVmType(self, sType):
        try:
            res = self.dbGetType(sType)
        except DbException as e:
            raise ExprException('db get %s return %s' % (sType, e.message))
        return res

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
                    res = self.dbGetType(sType)
                    if res['log'] == "ok." and 'res' in res and res['res'] is not None:
                        cell = res['res']
                        size = cell['size']
                    else:
                        raise DbException("get type %s failed" % sType)
                else:
                    size = lastCell['size']
            else:
                res = self.dbGetType(sType)
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
                indexMax = int(self._reSquareBrackets.findall(name)[0])
                name = name.split("[")[0]
            if name == member:
                if add > 0:
                    if add >= indexMax:
                        raise ExprException("member %s max index is %d, input %d, overflow" % (name, indexMax, add))
                    add *= int(cell['size'] / indexMax)
                return cell['offset'] + add
        raise ExprException("there is not member named %s in %s" % (member, structName))

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
                    layer = int(self._reLayer.match(orig)[0][1])
                except (TypeError, IndexError):
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
        if reg == "$retval":
            self._strFxpr = reg
        else:
            self._strFxpr = "%" + reg
            
        i = 0; end = len(cells); lastCell = None
        sMem = ""; origType = sType = "unkown"; tStruct = None; origMode = '->'

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

    def __getExprStruct(self, e):
        "nr=%1~(struct task_struct)->nr_dirtied"
        self.__checkBegExpr(e)

        showType, reg, argt, xpr = self.__getExprArgi(e)
        cells = self._splitPr(argt, xpr)
        return self._cellCheck(cells, reg, getCell=True)

    def _checkPoint(self, text):
        expr = splitExpr(text)[-1]
        try:
            return self.__getExprStruct(expr)
        except (ExprException, DbException) as e:
            self._footer.set_text("expression %s error, %s" % (expr, e.message))

    def __checkFormat(self, e):
        _, flag = e.split("=")
        self.__format = 'u'
        if flag[0] in "SUX":
            self.__format = str.lower(flag[0])

    def __checkBegExpr(self, e):
        if self._res['type'] == 'p':
            res = self._reSurfProbe.match(e)
        else:
            res = self._reSurfRet.match(e)
        if res is None:
            raise ExprException("error in expr %s." % e)
        return res

    def __checkExpr(self, e):
        self.__checkBegExpr(e)
        self.__checkFormat(e)

        showType, reg, argt, xpr = self.__getExprArgi(e)

        cells = self._splitPr(argt, xpr)
        res = self._cellCheck(cells, reg)
        if res['type'] == "struct":
            raise ExprException("last member is nested struct type, which is not completed.")
        return res

    def _checkExpr(self, expr):
        try:
            self.__checkExpr(expr)
        except ExprException as e:
            self._footer.set_text("expression %s error, %s." % (expr, e.message))
            return False
        return True

    def _checkExprs(self, text):
        es = splitExpr(text)
        fxprs = ""
        vars = []
        for expr in es:
            if not self._checkExpr(expr):
                return False, ""
            var, _ = expr.split("=", 1)
            if var in vars:
                self._footer.set_text("var %s is already used at previous expression" % var)
                return False, ""
            vars.append(var)
            fxprs += "%s=" % var + self._strFxpr + ' '
        return True, fxprs

    def _checkSpace(self, text):
        exprs = splitExpr(text)
        expr = exprs[-1]
        if expr == '':
            self._footer.set_text("do not input space")
            return
        self._checkExpr(expr)

    def _cb_check_pt(self, t):
        cell = self._checkPoint(t)
        if cell is not None:
            types = isStruct(cell['type'])
            if types == "struct":
                self._footer.set_text("last arg member is a nest struct. should add members")
            elif types is not None:
                self._footer.set_text("press tab to show %s info." % types)
            else:
                res = self.dbGetType(cell['type'])
                if res['log'] == "ok." and 'res' in res and res['res'] is not None:
                    cell = res['res']
                    self._footer.set_text("member: %s type: %s, size: %d" % (cell['name'], cell['type'], cell['size']))
                else:
                    self._footer.set_text("unknown type %s or db error" % (cell['type']))

    def _cb_edit_event(self, widget, t):
        if t == "":
            return
        lastT = t[-1]
        if lastT == ' ':
            self._checkSpace(t[:-1])
        elif lastT == ">":
            if t[-2] != "-":
                self._footer.set_text("should write as '->'")
            else:
                self._cb_check_pt(t)
        elif lastT == ".":
            self._cb_check_pt(t)

    def _cb_key_tab(self):
        t = self._eArgs.get_text()[0]
        if t == "":
            return
        lastT = t[-1]
        if lastT == ' ':
            self._checkExpr(t)
        elif lastT in ('@', '!'):
            l = len(t)
            if '%' in t:
                t += "(struct  *)"
            else:
                t += "(struct  *)%"
            self._eArgs.set_edit_text(t)
            self._eArgs.set_edit_pos(l + 8)
        elif lastT == '$':
            t += "retval"
            self._eArgs.set_edit_text(t)
        elif t.endswith("->") or lastT == ".":
            cell = self._checkPoint(t)
            if cell and 'type' in cell:
                sStruct = isStruct(cell['type'])
                if sStruct is None:
                    self._footer.set_text("last arg type %s, which is not a struct type" % cell['type'])
                    return
                tStruct = self._getVmStruct(sStruct)
                if tStruct['res'] is not None:
                    sel = CstructSelctor(tStruct['res'], self)
                    self.switch_widget(sel)
                else:
                    self._footer.set_text("get type %s failed" % sStruct)
            else:
                self._footer.set_text("some logic erro in %s, cell:%s" % (str(inspect.stack()[1]), str(cell)))

    def _cb_cancel_clk(self, widget):
        self.switch_widget(self._parent)

    def _cb_save_clk(self, widget):
        exprs = self._eArgs.get_text()[0]
        if self._checkExprs(self._eArgs.get_text()[0])[0]:
            self._res['args'] = exprs
            self._parent.updateTips()
            self.switch_widget(self._parent)
            # self._footer.set_text("expression {self._eArgs.get_text()[0]}")

    def _blankTips(self):
        s = "You can declare a variable to get the parameter information. Note that there should be no spaces in a single expression, and the expressions should be separated by space.\n"
        s += "eg. to visit struct member: comm=%0->comm\n"
        s += "    for skb_buff: ip_src=@(struct iphdr *)l3%1->saddr.\n"
        s += "    Cast pointer type conversion: segs=!(struct tcp_sock *)%1->gso_segs."
        return s

    def _parseFunc(self):
        s = "function information:\n"
        s += "    name: %s\n" % self._func['func']
        s += "    args: %%0, type: %s\n" % self._func['args'][0]
        for i, t in enumerate(self._func['args'][1:]):
            s += "          %%%d, type: %s\n" % (i + 1, t)
        s += "    return type: %s\n" % self._func['ret']
        s += "     declare in: %s:%d" % (self._func['file'], self._func['line'])
        return s

    def _cb_check_exprs(self, key):
        exprs = self._eArgs.get_text()[0]
        stat, s = self._checkExprs(exprs)
        if stat:
            self._footer.set_text("exprs is a good expr. xpr: %s" % s)

    def setupView(self):
        dummy = urwid.Divider()
        self._setupHeadFoot("set args, mode: %s" % self._res['type'], "input args, like a=%1,")

        lArgs = urwid.AttrWrap(urwid.Text("args:", align="right"), "body")
        self._eArgs = self._create_edit("", "%s" % self._res['args'], self._cb_edit_event)
        edits = urwid.Columns([('weight', 1, lArgs),
                               ('weight', 4, self._eArgs)])

        info = urwid.AttrWrap(urwid.Text(self._parseFunc()), "body")
        tips = urwid.AttrWrap(urwid.Text(self._blankTips()), "body")

        btnCancel = self._create_button("ca[n]cel", self._cb_cancel_clk)
        btnNxt = self._create_button("sav[e]", self._cb_save_clk)
        btns = urwid.Columns([btnCancel, dummy, btnNxt])

        self._regShortCtrl('k', self._cb_check_exprs, sendKey=True)
        frame = self._setupFrame([edits, dummy, info, dummy, tips, dummy, btns])
        return frame

    def addMem(self, mem):
        txt = self._eArgs.get_text()[0]
        txt = txt + mem
        self._eArgs.set_edit_text(txt)
        if txt[-1] == ']':
            self._eArgs.set_edit_pos(len(txt) - 1)
        else:
            self._eArgs.set_edit_pos(len(txt) + 1)

    def key_proc(self, key):
        if key == "tab":
            self._cb_key_tab()
            return


if __name__ == "__main__":
    pass
