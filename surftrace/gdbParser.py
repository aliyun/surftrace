# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     gdbParser
   Description :
   Author :       liaozhaoyan
   date：          2022/3/20
-------------------------------------------------
   Change Activity:
                   2022/3/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import hashlib
import re
from .baseParser import CbaseParser
from .execCmd import CexecCmd, CasyncCmdQue
from .surfException import FileNotExistException, InvalidArgsException


class CgdbParser(CbaseParser):
    def __init__(self, vmlinuxPath="", gdb=None):
        super(CgdbParser, self).__init__()
        self._res = {}

        self._reBrackets = re.compile(r"(?<=\().+?(?=\))")
        self._reSquareBrackets = re.compile(r"(?<=\[).+?(?=\])")
        self._reAngleBrackets = re.compile(r"(?<=\<).+?(?=\>)")
        self._reGdbVersion = re.compile(r"[\d]+\.[\d]+")
        self._rePaholeRem1 = re.compile(r"\/\* *[\d]+( *|: *[\d] *)\| *[\d]+ *\*\/")
        self._rePaholeRem2 = re.compile(r"\/\* *[\d]+ *\*\/")
        self._reRem = re.compile(r"\/\*.*\*\/")

        self._cmd = CexecCmd()
        if gdb is None:
            gdb = self._checkGdbExist()
        if vmlinuxPath == "":
            vmlinuxPath = self.__getVmlinuxPath()
        if not os.path.exists(vmlinuxPath):
            raise FileNotExistException("vmlinux %s is not found." % (vmlinuxPath))

        cmd = '%s %s' % (gdb, vmlinuxPath)
        self.__want = "(gdb)"
        self.__aCmd = CasyncCmdQue(cmd)
        self._read()
        self._write('set pagination off')
        self._read()
        self._pSize = self.__showTypeSize("void *")
        self._iSize = self.__showTypeSize("int")
        self._checkGdbVer()

    def __del__(self):
        self.__aCmd.terminate()

    def _write(self, l):
        self.__aCmd.writeLine(l)

    def _read(self, tries=100):
        return self.__aCmd.readw(self.__want, tries)

    def _checkGdbExist(self):
        cmd = 'which gdb'
        line = self._cmd.cmd(cmd)
        if line == "":
            raise FileNotExistException("gdb is not install")
        return "gdb"

    def _checkGdbVer(self):
        self._write("show version")
        lines = self._read().split('\n')
        res = self._reGdbVersion.search(lines[0])
        if res is None:
            raise FileNotExistException("%s, unknown gdb version." % lines[0])
        major, minor = res.group().split(".")
        if int(major) < 8:
            s = "you gdb version is %s, lower than 8.x." % res.group()
            s += " A high version of the gdb is required to achieve full functionality.\n"
            s += "if your arch is x86_64, you can wget http://pylcc.openanolis.cn/gdb/ then set gdb path args."
            raise FileNotExistException(s)

    def __getVmlinuxPath(self):
        name = self._cmd.cmd('uname -r')
        return "/usr/lib/debug/usr/lib/modules/" + name + "/vmlinux"

    def _showStruct(self, sStruct):
        self._write("ptype /o %s" % sStruct)
        return self._read()

    def __showTypeSize(self, sType):
        if "..." in sType:
            return 0
        cmd = "p sizeof(%s)" % sType
        self._write(cmd)
        readStr = self._read().split('\n')[0]
        try:
            nStr = readStr.split('=')[1].strip()
        except IndexError:
            return 0
        return int(nStr)

    def _showTypeSize(self, sType):
        if "*" in sType:
            return self._pSize
        elif sType.startswith("enum"):
            return self._iSize
        return self.__showTypeSize(sType)

    def _showMemberOffset(self, member, structName):
        structName = structName.replace("*", "")
        cmd = "p &((%s*)0)->%s" % (structName, member)
        self._write(cmd)
        s = self._read()
        if s is None:
            raise InvalidArgsException("%s is not in %s" % (member, structName))
        readStr = s.strip()
        nStr = self._reAngleBrackets.findall(readStr)[0]
        if "+" not in nStr:
            return 0
        return int(nStr.split("+")[1])

    def showMemberOffset(self, member, structName):
        self._showMemberOffset(member, structName)

    def _setupRes(self):
        self._res = {'log': 'ok.'}

    def _argFuncSplit(self, argStr):
        args = []
        arg = ""
        count = 0

        for a in argStr:
            if count == 0 and a == ",":
                args.append(arg.strip())
                arg = ""
                continue
            elif a == "(":
                count += 1
            elif a == ")":
                count -= 1
            arg += a
        if arg != "":
            args.append(arg.strip())
        return args

    def _showFuncs(self, func):
        cmd = "i func %s" % func
        self._write(cmd)
        return self._read()

    def getFunc(self, func, ret=None, arg=None):
        self._setupRes()
        if len(func) < 2:
            return {"log": "func len should bigger than 2.", "res": None}

        self._res['res'] = []
        func = func.replace("%", "*")
        func = "^" + func
        lines = self._showFuncs(func).split('\n')
        File = ""
        funcs = 0
        for line in lines[1:]:
            if line == "":
                continue
            elif line.startswith("(gdb)"):
                break
            elif line.startswith("File "):
                _, sFile = line.split(" ", 1)
                File = sFile[:-1]
            elif line.endswith(");"):
                # 8:	static int __paravirt_pgd_alloc(struct mm_struct *);
                line = line[:-2]
                if ':' in line:
                    lineNo, body = line.split(":", 1)
                else:
                    lineNo = '0'
                    body = line
                head, args = body.split("(", 1)
                # args = [x.strip() for x in args.split(",")]
                args = self._argFuncSplit(args)
                if "*" in head:
                    ret, func = head.rsplit("*", 1)
                    ret += "*"
                else:
                    ret, func = head.rsplit(" ", 1)
                funcd = {'func': func, 'args': args, 'ret': ret, 'line': int(lineNo), 'file': File}
                self._res['res'].append(funcd)

                funcs += 1
                if funcs > 20:
                    break
        return self._res

    def _stripRem(self, line):
        return self._reRem.sub("", line).strip()

    def _splitStructLine(self, line):
        rd = {"offset": None, "size": None, "bits": None}

        res = self._rePaholeRem1.search(line)
        if res:
            l = res.group()[2:-2].strip()
            # /*   19: 0   |     1 */        unsigned char skc_reuse : 4;
            # /*   19: 4   |     1 */        unsigned char skc_reuseport : 1;
            off, size = l.split('|', 1)
            rd["size"] = int(size.strip())
            if ":" in off:
                off, bits = off.split(":", 1)
                rd['bits'] = bits.strip()  # offset
            rd["offset"] = int(off.strip())
        else:
            res = self._rePaholeRem2.search(line)
            if res:
                l = res.group()[2:-2].strip()
                # /*    8      |     4 */        union {
                # /*                 4 */            unsigned int skc_hash;
                # /*                 4 */            __u16 skc_u16hashes[2];
                size = l.strip()
                rd["size"] = int(size.strip())
        rd["line"] = self._stripRem(line)
        return rd

    def _parseMember(self, sStruct, line, pre="", off=0):
        """struct list_head *         next;"""
        """void (*func)(struct callback_head *);"""
        """unsigned int               p:1;"""
        if ";" not in line:
            return
        rd = self._splitStructLine(line)
        l = rd['line']
        bits = ""
        if ':' in l:
            l, bits = l.rsplit(" : ", 1)
            bits = "%s:%s" % (rd["bits"], bits)
        if l[-1] == ')':
            _, func = l.split("(*", 1)
            func, _ = func.split(")", 1)
            types = line.replace(" (*%s)(" % func, " (*)(", 1)
            types = re.sub(" +", " ", types)
            name = func
        elif '*' in l:
            types, name = l.rsplit("*", 1)
            types = types + "*"
            name = name.strip("; ")
        else:
            types, name = l.rsplit(" ", 1)
            types = types.strip()
            name = name.strip("; ")
        name = pre + name

        if rd["offset"] is None:
            rd["offset"] = off
        cell = {"type": types, "name": name, "offset": rd["offset"],
                "size": rd["size"], "bits": bits}
        self._res['res']['cell'].append(cell)

    def _parseBox(self, sStruct, lines, pre):
        """union {"""
        """} pci;"""
        rd = self._splitStructLine(lines[0])
        t = rd['line'].split(" ", 1)[0]
        if t in ["union", "struct"]:
            lastLine = lines[-1].strip()
            if not lastLine.startswith("};"):
                npre, _ = lastLine[1:].split(";", 1)
                _, npre = npre.rsplit(" ", 1)
                pre += npre.strip() + "."
            self._parseLoop(sStruct, lines, pre, rd["offset"])

    def _parseLoop(self, sStruct, lines, pre, off=0):
        qCount = 0
        box = []
        for line in lines[1:-1]:
            lCount = line.count("{")
            rCount = line.count("}")
            qCount += lCount - rCount
            if qCount > 0:
                box.append(line)
            elif len(box) > 0:
                box.append(line)
                self._parseBox(sStruct, box, pre)
                box = []
            else:
                self._parseMember(sStruct, line, pre, off)

    def getStruct(self, sStruct):
        self._setupRes()
        lines = self._showStruct(sStruct).split('\n')
        l = self._splitStructLine(lines[0])['line']
        name = l.split('=', 1)[1]
        name = name.split('{', 1)[0].strip()
        self._res['res'] = {"name": name, "size": self._showTypeSize(name), "cell": []}
        self._parseLoop(name, lines, "")
        self._res['res']['members'] = len(self._res['res']['cell'])
        return self._res

    def getType(self, sType):
        self._setupRes()
        lines = self._showStruct(sType).split('\n')
        _, alias = lines[0].split("=", 1)
        alias = alias.strip()
        size = self._showTypeSize(sType)
        res = {'name': sType, 'type': alias, 'size': size}
        self._res['res'] = res
        return self._res

    def __endAdd1(self, s):
        if "+" not in s:
            return s
        start, num = s.split("+", 1)
        num = int(num) + 1
        return "%s+%d" % (start, num)

    def parserLine(self, line):
        cmd = "i line %s" % line
        self._write(cmd)
        s = self._read(tries=100)
        md5s = []
        cnt = 0
        for l in s.split("\n")[:-1]:
            res = self._reAngleBrackets.findall(l)
            if res is None:
                raise InvalidArgsException("%s is not a func head, eg. fs/stat.c:145", line)
            elif len(res) == 1:
                beg = end = res[0]
            else:
                beg = res[0]
                end = res[1]
            cmd = "disas %s,%s" % (beg, end)
            self._write(cmd)
            try:
                show = self._read()
            except:
                continue
            md5 = hashlib.md5(show).hexdigest()
            if md5 not in md5s:
                cnt += 1
                md5s.append(md5)
                print("show disas %d, %s:" % (cnt, md5))
                print(self._stripGdb(show))

    def _stripGdb(self, line):
        ls = line.split('\n')
        return '\n'.join(ls[:-1])

    def disasFun(self, func):
        cmd = "disas /m %s" % func
        self._write(cmd)
        show = self._read()
        print(self._stripGdb(show))


if __name__ == "__main__":
    pass
