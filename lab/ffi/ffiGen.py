# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     ffiGen
   Description :
   Author :       liaozhaoyan
   date：          2022/12/1
-------------------------------------------------
   Change Activity:
                   2022/12/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from surftrace.dbParser import CdbParser


class CffiGen(object):
    def __init__(self, db):
        super(CffiGen, self).__init__()
        self._parser = CdbParser(db)
        self._baseType = (
                          "char", "unsigned char", "signed char",
                          "short", "unsigned short", "signed short",
                          "int", "unsigned int", "signed int",
                          "long int", "unsigned long int", "signed long int",
                          "long long int", "long long unsigned int", "signed long long int", "unsigned long long int",
                          "long unsigned int", "long long", "long",
                          "float", "double",
                          "void *", "void", "_Bool",
                          )
        self._lines = []
        self._cells = []
        self._tails = []

    def _getType(self, t):
        if '*' in t:
            return self._parser.getType("void *")
        elif t in self._baseType:
            return self._parser.getType(t)
        elif ' ' in t:
            head, body = t.split(" ", 1)
            if head in ("struct", "union", "enum"):
                return self._parser.getStruct(t)
            else:
                raise ValueError("bad head: %s" % t)
        else:
            res = self._parser.getType(t)
            alias = res["res"]["type"]
            if alias == t:
                return self._parser.getStruct(t)
            else:
                return self._getType(alias)

    def outType(self, t, res):
        if t != res['name']:
            line = "typedef %s %s;" % (res['name'], t)
            self._lines.insert(0, line)

    def _checkMemberType(self, sType):
        if sType.endswith("*"):  # for function void (*)(struct callback_head)
            sType = sType.replace("*", "")

        if sType in self._cells or sType in self._baseType:
            return ""
        if sType.startswith("struct ") or sType.startswith("union "):
            res = self._getType(sType)
            if res['res'] and "cell" in res['res']:
                self._cells.append(sType)
                self._tails.append(res['res'])
            return sType + ';\n'
        elif "(" in sType:
            return ""
        elif sType.startswith("enum"):
            return ""
        elif sType in ("struct", "union"):
            self._cells.append(sType)
            return ""
        else:
            print(sType)

    def _anonStruct(self, res, topName, step):
        pre = ""
        head = res["name"].split(" ")[0]
        tabs = '\t' * step
        line = "%s%s {\n" % (tabs, head)
        for cell in res["cell"]:
            sType = cell["type"]
            sName = cell["name"]
            if "$" in sType:
                sub = self._getType(sType)['res']
                self._anonStruct(sub, sName, step + 1)
            else:
                if '[' in sType:
                    sType, sArr = sType.split("[", 1)
                    sName += "[" + sArr
                pre += self._checkMemberType(sType)
                line += "%s\t%s %s;\n" % (tabs, sType, sName)
        line += "%s} %s;\n" % (tabs, topName)
        return pre, line

    def outStruct(self, res, step):
        name = res["name"]
        if name not in self._cells:
            self._cells.append(name)
        tabs = '\t' * step
        if name.startswith("struct ") or name.startswith("union "):
            pre = ""
            line = "%s%s {\n" % (tabs, name)
            for cell in res["cell"]:
                sType = cell["type"]
                sName = cell["name"]
                if sName == "$":
                    print("anony members.")
                    sName = ""
                if "$" in sType:
                    sub = self._getType(sType)['res']
                    apre, aline = self._anonStruct(sub, sName, step + 1)
                    pre += apre
                    line += aline
                else:
                    if '[' in sType:
                        sType, sArr = sType.split("[", 1)
                        sName += "[" + sArr
                    pre += self._checkMemberType(sType)
                    line += "%s\t%s %s;\n" % (tabs, sType, sName)
            line += "%s};\n" % tabs
            self._lines.append(pre + line)

    def gen(self, t):
        if '[' in t:
            t, _ = t.split('[', 1)
        if t in self._cells or t in self._baseType:
            return

        res = self._getType(t)['res']
        if "cell" in res:
            self.outStruct(res, 0)
        else:
            self.outType(t, res)

    def out(self):
        for r in self._tails:
            self.outStruct(r, 0)
        return "\n".join(self._lines)


if __name__ == "__main__":
    g = CffiGen("bpf.db")
    g.gen("int")
    g.gen("u64[63]")
    g.gen("iw_handler")
    g.gen("struct task_struct")
    g.gen("struct mm_struct")
    g.gen("struct data_t")
    print(g.out())
    pass
