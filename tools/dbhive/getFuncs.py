# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     getFuncs
   Description :
   Author :       liaozhaoyan
   date：          2021/12/1
-------------------------------------------------
   Change Activity:
                   2021/12/1:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import os
import select
from select import epoll as CPoll
import shlex
from subprocess import PIPE, Popen
import sqlite3
import json
import re
import eventlet

ON_POSIX = 'posix' in sys.builtin_module_names


class CasyncCmdQue(object):
    def __init__(self, cmd):
        super(CasyncCmdQue, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, close_fds=ON_POSIX)
        self.__e = CPoll()
        self.__e.register(self.__p.stdout.fileno(), select.EPOLLIN)

    def __del__(self):
        self.__p.kill()

    def write(self, cmd):
        try:
            self.__p.stdin.write(cmd.encode())
            self.__p.stdin.flush()
        except IOError:
            return -1

    def writeLine(self, cmd):
        self.write(cmd + "\n")

    def read(self, tmout=0.2, l=16384):
        while True:
            es = self.__e.poll(tmout)
            if not es:
                return ""
            for f, e in es:
                if e & select.EPOLLIN:
                    s = os.read(f, l).decode()
                    return s
                elif e & select.EPOLLERR:
                    raise OSError("epoll error.")
                elif e & select.EPOLLHUP:
                    raise OSError("epoll hup error.")
                else:
                    raise OSError(f"unknown catch able events {e}")

    def readw(self, want, tries=20):
        i = 0
        r = ""
        while i < tries:
            line = self.read()
            if want in line:
                return r + line
            r += line
            i += 1
        raise OSError("get want args %s overtimes" % want)

    def terminate(self):
        self.writeLine("q")
        self.__p.terminate()
        return self.__p.wait()

class CgetVminfo(object):
    def __init__(self, vmPath, waits=20):
        super(CgetVminfo, self).__init__()
        # print(vmPath)
        self._gdb = CasyncCmdQue("gdb %s" % vmPath)
        self._gdb.readw("(gdb)", waits)
        self._gdb.writeLine("set pagination off")
        self._gdb.readw("(gdb)")
        self._gdb.writeLine("set max-value-size unlimited")
        self._gdb.readw("(gdb)")

    def __del__(self):
        if hasattr(self, "_gdb"):
            self._gdb.terminate()

    def genType(self, t):
        self._gdb.writeLine(f"ptype {t}")
        r = self._gdb.readw("(gdb)").split("\n")[0]
        _, alias = r.split("=", 1)
        alias = alias.strip()

        self._gdb.writeLine(f"p sizeof({t})")
        r = self._gdb.readw("(gdb)").split("\n")[0]
        _, size = r.split("=", 1)
        size = int(size.strip())
        return [alias, size]

    def showTypeSize(self, t):
        self._gdb.writeLine(f"p sizeof({t})")
        r = self._gdb.readw("(gdb)").split("\n")[0]
        _, size = r.split("=", 1)
        return int(size.strip())

    def showStruct(self, sStruct):
        self._gdb.writeLine("ptype /o %s" % sStruct)
        return self._gdb.readw("(gdb)", 80)

    def genFuncs(self, fName="funs.txt"):
        self._gdb.writeLine("i functions")
        with open(fName, 'w') as f:
            s = "dummy"
            while "\n(gdb)" not in s:
                s = self._gdb.read(tmout=240)
                f.write(s)

    def genTypes(self, fName="types.txt"):
        self._gdb.writeLine("i types")
        with open(fName, 'w') as f:
            s = "dummy"
            while "\n(gdb)" not in s:
                s = self._gdb.read(tmout=240)
                f.write(s)


class CgenfuncsDb(object):
    def __init__(self, dbName, build=True):
        self._db = None
        self._res = None
        self._setupDb(dbName, build)
        self._reTypeLine = re.compile(r"[\d]+:")
        self._rePaholeRem1 = re.compile(r"\/\* *[\d]+( *|: *[\d] *)\| *[\d]+ *\*\/")
        self._rePaholeRem2 = re.compile(r"\/\* *[\d]+ *\*\/")
        self._reRem = re.compile(r"\/\*.*\*\/")
        self._banTypes = []

    def __del__(self):
        if self._db is not None:
            self._db.commit()
            self._db.close()

    def _setupDb(self, dbName, build):
        if not build:
            self._db = sqlite3.connect(dbName)
            return
        if os.path.exists(dbName):
            os.remove(dbName)
        self._db = sqlite3.connect(dbName)
        cur = self._db.cursor()
        sql = """CREATE TABLE files ( 
                          id INTEGER PRIMARY KEY autoincrement,
                          file TEXT
                );"""
        cur.execute(sql)
        sql = """CREATE TABLE funs ( 
                  id INTEGER PRIMARY KEY autoincrement,
                  func VARCHAR (128),
                  args JSON,
                  ret VARCHAR (64),
                  line INTEGER,
                  fid INTEGER, 
                  module VARCHAR (64)
        );"""
        cur.execute(sql)
        sql = """CREATE TABLE structs ( 
                          id INTEGER PRIMARY KEY autoincrement,
                          name VARCHAR (64),
                          members INTEGER,
                          bytes INTEGER
                );"""
        cur.execute(sql)
        sql = """CREATE TABLE members ( 
                                  id INTEGER PRIMARY KEY autoincrement,
                                  fid INTEGER,
                                  types VARCHAR (128),
                                  name VARCHAR (64),
                                  offset INTEGER,
                                  bytes INTEGER,
                                  bits VARCHAR (16) DEFAULT ""
                        );"""
        cur.execute(sql)
        sql = """CREATE TABLE types ( 
                                  id INTEGER PRIMARY KEY autoincrement,
                                  name VARCHAR (64),
                                  alias VARCHAR (64),
                                  bytes INTEGER
                        );"""
        cur.execute(sql)
        cur.close()

    def _arg_split(self, argStr):
        args = []
        arg  = ""
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

    def _funcs(self, funcPath, module="vm"):
        cur = self._db.cursor()
        with open(funcPath, 'r') as f:
            fid = 0
            for index, line in enumerate(f):
                line = line[:-1]
                if line == "":
                    continue
                elif line.startswith("(gdb)"):
                    break
                elif line.startswith("File "):
                    if line.endswith(".h:"):    # do not add any
                        fid = -1
                    else:
                        _, sFile = line.split(" ", 1)
                        sql = f'''INSERT INTO files (file) VALUES ("{sFile[:-1]}")'''
                        cur.execute(sql)
                        fid = cur.lastrowid
                elif fid > 0 and line.endswith(");"):
                    #8:	static int __paravirt_pgd_alloc(struct mm_struct *);
                    line = line[:-2]
                    lineNo, body = line.split(":", 1)
                    head, args = body.split("(", 1)
                    # args = [x.strip() for x in args.split(",")]
                    args = self._arg_split(args)
                    if "*" in head:
                        ret, func = head.rsplit("*", 1)
                        ret += "*"
                    else:
                        ret, func = head.rsplit(" ", 1)
                    sql = f'''INSERT INTO funs (func, args, ret, line, fid, module) VALUES \
                    ("{func}", '{json.dumps(args)}', "{ret.strip()}", {lineNo}, {fid}, "{module}")'''
                    cur.execute(sql)
        cur.close()

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
                rd["size"] = int(size)
        rd["line"] = self._stripRem(line)
        return rd

    def _parseMember(self, sStruct, line, pre="", off=0):
        """struct list_head *         next;"""
        """void (*func)(struct callback_head *);"""
        """unsigned int               p:1;"""
        if ";" not in line:
            """/* total size (bytes):    4 */"""
            if "total size (bytes):" in line:
                size = line.split(":", 1)[1]
                size = size.split("*", 1)[0].strip()
                self._res['res']['size'] = size
            return
        rd = self._splitStructLine(line)
        l = rd['line']
        bits = ""
        if ':' in l:
            l, bits = l.rsplit(" : ", 1)
            bits = "%s:%s" % (rd["bits"], bits)
        if '(' in l:
            _, func = l.split("(*", 1)
            func, _ = func.split(")", 1)
            types = l.replace(" (*%s)(" % func, " (*)(", 1)
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
            if rd["offset"] is None:
                rd["offset"] = 0
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

    def _getStruct(self, gdb, sStruct):
        self._res = {"log": "struct"}
        lines = gdb.showStruct(sStruct).split('\n')
        self._res['res'] = {"name": sStruct, "size": 0, "cell": []}
        self._parseLoop(sStruct, lines, "")
        self._res['res']['members'] = len(self._res['res']['cell'])
        return self._res

    def _struct_is_in(self, cur, sStruct):
        sql = f"SELECT name FROM structs WHERE name = '{sStruct}'"
        res = cur.execute(sql)
        if res is None:
            return False
        r = res.fetchone()
        if r is None:
            return False
        return True

    def _struct(self, cur, gdb, sStruct):
        if self._struct_is_in(cur, sStruct):
            return
        res = self._getStruct(gdb, sStruct)
        if res is None:
            return
        dStruct = res['res']
        sql = f'''INSERT INTO structs (name, members, bytes) VALUES \
                                   ("{dStruct['name']}", {dStruct['members']}, {dStruct['size']})'''
        cur.execute(sql)
        fid = cur.lastrowid
        for cell in dStruct['cell']:
            sql = f'''INSERT INTO members (fid, types, name, offset, bytes, bits) VALUES \
                        ({fid}, "{cell['type']}", "{cell['name']}", {cell['offset']}, {cell['size']}, "{cell['bits']}")'''
            try:
                cur.execute(sql)
            except sqlite3.OperationalError:
                print(f"bad {sql}, for {dStruct['name']}")

    def _save_type(self, cur, gdb, t):
        alias, size = gdb.genType(t)
        sql = f'INSERT INTO types (name, alias, bytes) VALUES ("{t}", "{alias}", {size})'
        cur.execute(sql)
        if alias == "struct {" or alias == 'union {':   # there is no alias struct in this type
            self._struct(cur, gdb, t)

    def _type_is_in(self, cur, t):
        if t in self._banTypes:
            return True
        sql = f"SELECT name FROM types WHERE name = '{t}'"
        res = cur.execute(sql)
        if res is None:
            return False
        r = res.fetchone()
        if r is None:
            return False
        return True

    def _check_type(self, cur, gdb, t):
        if not self._type_is_in(cur, t):
            try:
                self._save_type(cur, gdb, t)
            except ValueError:
                self._banTypes.append(t)
                print(f"failed to parse type {t}")

    def _types(self, typePath, cur, gdb):
        with open(typePath, 'r') as f:
            for i, line in enumerate(f):
                if i < 1 or line.startswith("(gdb)"):    # skip head and end
                    continue
                if self._reTypeLine.match(line):
                    line = line.split(':', 1)[1]
                line = line.strip()
                if line != "":  # strip blank line
                    if line.startswith("File "):  # jump File
                        continue
                    if line.startswith("enum "):
                        continue
                    if line.startswith("struct ") or line.startswith("union "):
                        self._struct(cur, gdb, line[:-1])
                        continue
                    if line.startswith("typedef "):  # for typedef
                        sType = line.rsplit(" ", 1)[1]
                        self._check_type(cur, gdb, sType[:-1])  # skip last ;
                        continue
                    if line.startswith("__int128"):
                        line = "__int128"
                    self._check_type(cur, gdb, line)

    def _parseElf(self, cur, gdb, mod):
        try:
            gdb.genTypes("types.txt")
            gdb.genFuncs("funcs.txt")
        except OSError as e:
            print(f"parse error. report {e}")
            return
        self._funcs("funcs.txt", mod)
        self._types("types.txt", cur, gdb)

    def pasrseVmLinux(self, vmPath):
        cur = self._db.cursor()
        gdb = CgetVminfo(vmPath, waits=800)
        self._save_type(cur, gdb, "void *")
        self._parseElf(cur, gdb, "vm")
        cur.close()

    def _parse_ko(self, path, fName):
        if fName.endswith("ko"):
            mod = fName.rsplit(".", 1)[0]
        else:
            mod = fName.rsplit(".", 2)[0]
        try:
            gdb = CgetVminfo(os.path.join(path, fName), 80)
        except OSError as e:
            print(f"load module {fName} error. report {e}")
            return
        cur = self._db.cursor()
        self._parseElf(cur, gdb, mod)
        cur.close()

    def parse_kos(self, path):
        g = os.walk(path)
        for path, dirL, fileL in g:
            for fName in fileL:
                if fName.endswith("ko") or fName.endswith("ko.debug"):
                    eventlet.monkey_patch()
                    try:
                        with eventlet.Timeout(6 * 60):
                            self._parse_ko(path, fName)
                    except (OSError, eventlet.timeout.Timeout) as e:
                        print(f"parse {fName} failed report {e}")

if __name__ == "__main__":
    d = CgenfuncsDb("./info-5.13.0-21-generic.db")
    d.pasrseVmLinux("./deb/usr/lib/debug/boot/vmlinux-5.13.0-21-generic")
    d.parse_kos("./deb")
    pass
