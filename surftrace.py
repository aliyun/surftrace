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
import signal
import sys
import os
import socket
import shlex
import argparse
import struct
import json
import hashlib
from subprocess import PIPE, Popen
from threading import Thread
import select
import traceback
import sqlite3
ON_POSIX = 'posix' in sys.builtin_module_names

LBC_COMPILE_PORT = 7654
LBCBuffSize = 80 * 1024 * 1024
save2File = False
cmdStrings = "trap ':' INT QUIT TERM PIPE HUP\n"

def saveCmd(s):
    global save2File
    global cmdStrings
    if save2File:
        cmdStrings += s + "\n"

def getValueFromStr(s):
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    else:
        return int(s)

def headTrans(head, value):
    type = head.split('_', 1)[0]
    if type == "ip":
        v = getValueFromStr(value)
        value = socket.inet_ntoa(struct.pack('>I', socket.htonl(v)))
    elif type == "B16":
        v = getValueFromStr(value)
        v = struct.unpack('H', struct.pack('>H', v))
        value = "%x" % v
    elif type == "B32":
        v = getValueFromStr(value)
        v = struct.unpack('I', struct.pack('>I', v))
        value = "%x" % v
    elif type == "B64":
        v = getValueFromStr(value)
        v = struct.unpack('Q', struct.pack('>Q', v))
        value = "%x" % v
    elif type == "b16":
        v = getValueFromStr(value)
        v = struct.unpack('H', struct.pack('>H', v))
        value = "%d" % v
    elif type == "b32":
        v = getValueFromStr(value)
        v = struct.unpack('I', struct.pack('>I', v))
        value = "%d" % v
    elif type == "b64":
        v = getValueFromStr(value)
        v = struct.unpack('Q', struct.pack('>Q', v))
        value = "%d" % v
    return "%s=%s" % (head, value)

def invHeadTrans(head, value):  #为 filter 翻转
    type = head.split('_', 1)[0]
    if type == "ip":
        v = struct.unpack('I',socket.inet_aton(value))[0]
        value = "0x%x" % v
    elif type == "B16" or type == "b16":
        v = getValueFromStr(value)
        v = struct.unpack('H', struct.pack('>H', v))
        value = "%x" % v
    elif type == "B32" or type == 'b32':
        v = getValueFromStr(value)
        v = struct.unpack('I', struct.pack('>I', v))
        value = "%x" % v
    elif type == "B64" or type == 'b64':
        v = getValueFromStr(value)
        v = struct.unpack('Q', struct.pack('>Q', v))
        value = "%x" % v
    return head, value

class RootRequiredException(Exception):
    def __init__(self, message):
        super(RootRequiredException, self).__init__(message)
        self.message = message

class FileNotExistException(Exception):
    def __init__(self, message):
        super(FileNotExistException, self).__init__(message)
        self.message = message

class FileNotEmptyException(Exception):
    def __init__(self, message):
        super(FileNotEmptyException, self).__init__(message)
        self.message = message

class InvalidArgsException(Exception):
    def __init__(self, message):
        super(InvalidArgsException, self).__init__(message)
        self.message = message

class DbException(Exception):
    def __init__(self, message):
        super(DbException, self).__init__(message)
        self.message = message

class ExprException(Exception):
    def __init__(self, message):
        super(ExprException, self).__init__(message)
        self.message = message

class ExecException(Exception):
    def __init__(self, message):
        super(ExecException, self).__init__(message)
        self.message = message


# copy from surf expression.py
probeReserveVars = ('common_pid', 'common_preempt_count', 'common_flags', 'common_type')
archRegd = {'x86_64': ('di', 'si', 'dx', 'cx', 'r8', 'r9', 'ax', 'bx'),
            'x86': ('di', 'si', 'dx', 'cx', 'ax', 'bx'),
            'aarch64': ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7'),}

def maxNameString(cells, t):
    rs = cells[0][t]
    ret = ""
    for i, r in enumerate(rs):
        for f in cells[1:]:
            sFunc = f[t]
            if len(sFunc) < i or sFunc[i] != r:
                return ret
        ret += r
    return ret

def isStruct(text):
    strips = ("const ", "volatile ")
    for s in strips:
        text = text.replace(s, "")
    text = text.strip()
    if text.startswith("struct ") or text.startswith("union "):
        return text
    return None

def splitExpr(text):
    es = []
    e = ""
    count = 0
    for c in text:
        if c == '(':
            count += 1
        elif c == ")":
            count -= 1
            if count < 0:
                return None
        elif count == 0 and c == " ":
            if e != "": es.append(e)
            e = ""
            continue
        e += c
    if e != "": es.append(e)
    return es

def spiltInputLine(line):
    res = {}
    es = splitExpr(line)
    esLen = len(es)
    if esLen < 2:
        raise ExprException("%s is a single expression" % line)
    if es[0] not in ('p', 'r', 'e'):
        raise ExprException("not support %s event." % es[0])
    res['type'] = es[0]
    res['symbol'] = es[1]
    if esLen >= 3:
        if es[-1].startswith("f:"):
            res['filter'] = es[-1][2:]
            res['args'] = " ".join(es[2:-1])
        else:
            res['filter'] = ""
            res['args'] = " ".join(es[2:])
    else:
        res['filter'] = ""; res['args'] = ""
    return res

def unpackRes(res):
    s = "%s %s" % (res['type'], res['symbol'])
    if res['filter'] == "":
        if res['args'] == "":
            return s
        else:
            return s + " %s" % res['args']
    else:
        if res['args'] == "":
            return s + " f:%s" % res['filter']
        else:
            return s + " %s f:%s" % (res['args'], res['filter'])

def stripPoint(sStruct):
    return sStruct.strip("*").strip()

def regIndex(reg, arch='x86'):
    regs = archRegd[arch]
    try:
        return regs.index(reg)
    except ValueError:
        raise ExprException('%s is not a %s register.' % (reg, arch))

def transReg(i, arch='x86'):
    try:
        return archRegd[arch][i]
    except IndexError:
        raise ExprException('reg index %d overflow.' % i)

class CasyncPipe(Thread):
    def __init__(self, f, func):
        if not os.path.exists(f):
            FileNotExistException("%s is not exist." % f)
        self.__callBack = func
        super(CasyncPipe, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__pipe = open(f, 'r')
        self.__loop = True
        self.start()
        
    def newCb(self, func):
        self.__callBack = func

    def run(self):
        while self.__loop:
            line = self.__pipe.readline().strip()
            self.__callBack(line)

    def terminate(self):
        self.__loop = False
        self.join(1)

class CexecCmd(object):
    def __init__(self):
        pass

    def cmd(self, cmds):
        p = Popen(shlex.split(cmds), stdout=PIPE)
        if sys.version_info.major == 2:
            return p.stdout.read().strip()
        else:
            return p.stdout.read().decode().strip()

    def system(self, cmds):
        cmds = cmds.replace('\0', '').strip()
        return os.popen(cmds).read(8192)

class CasyncCmdQue(object):
    def __init__(self, cmd):
        super(CasyncCmdQue, self).__init__()
        self.daemon = True  # thread dies with the program
        self.__p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, close_fds=ON_POSIX)
        self.__e = select.epoll()
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
                    if sys.version_info.major == 2:
                        s = os.read(f, l)
                    else:
                        s = os.read(f, l).decode()
                    return s

    def readw(self, want, tries=100):
        i = 0
        r = ""
        while i < tries:
            line = self.read()
            if want in line:
                return r + line
            r += line
            i += 1
        raise Exception("get want args %s overtimes" % want)

    def terminate(self):
        self.__p.terminate()
        return self.__p.wait()

class ftrace(object):
    def __init__(self, show=False, echo=True):
        super(ftrace, self).__init__()
        self._show = show
        self._echo = echo
        self._c = CexecCmd()
        if self._show:
            self.baseDir = ""
        else:
            self.__checkRoot()
            self.baseDir = self.__getMountDir()
        self.pipe = None
        self._stopHook = []
        self._single = True
        self.__ps = []

    def __getMountDirStr(self):
        cmd = "mount"
        lines = self._c.cmd(cmd)
        for l in lines.split('\n'):
            if "type debugfs" in l:
                return l
        return None

    def __checkRoot(self):
        cmd = 'whoami'
        line = self._c.cmd(cmd).strip()
        if line != "root":
            raise RootRequiredException('this app need run as root')

    def __getMountDir(self):
        s = self.__getMountDirStr()
        if s is None:
            return None
        else:
            return s.split(' ')[2]

    def tracePre(self, buffSize=2048):
        pBuffersize = self.baseDir + "/tracing/instances/surftrace/buffer_size_kb"
        self._echoPath(pBuffersize, "%d" % buffSize)
        pTrace = self.baseDir + "/tracing/instances/surftrace/trace"
        self._echoPath(pTrace)

    def _transEcho(self, value):
        value = re.sub(r"[\"\']", "", value)
        return value

    def _echoPath(self, path, value=""):
        cmd = "echo %s > %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY)
        v = self._transEcho(value)
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, report:%s." % (v, path, e.strerror))
        finally:
            os.close(fd)

    def _echoFilter(self, path, value):
        cmd = "echo %s > %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY)
        v = value[1:-1]
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, report:%s." % (v, path, e.strerror))
        finally:
            os.close(fd)

    def _echoDPath(self, path, value=""):
        cmd = "echo %s >> %s" % (value, path)
        saveCmd(cmd)
        if self._echo:
            print(cmd)

        fd = os.open(path, os.O_WRONLY|os.O_APPEND)
        v = self._transEcho(value)
        try:
            os.write(fd, v.encode())
        except OSError as e:
            raise InvalidArgsException("set arg %s to %s failed, return %s." %(v, path, e.strerror))
        finally:
            os.close(fd)

    def procLine(self, line):
        print(line)
        return 0

    def __stopTracing(self):
        pOn = self.baseDir + "/tracing/instances/surftrace/tracing_on"
        self._echoPath(pOn, "0")

    def _start(self):
        pOn = self.baseDir + "/tracing/instances/surftrace/tracing_on"
        self._echoPath(pOn, "1")
        self._stopHook.insert(0, self.__stopTracing)
        signal.signal(signal.SIGINT, self.signalHandler)

    def start(self):
        self._single = True
        self._start()
        pipe = self.baseDir + "/tracing/instances/surftrace/trace_pipe"
        self.pipe = CasyncPipe(pipe, self.procLine)
        saveCmd("cat %s" % pipe)

    def signalHandler(self, signalNumber, frame):
        if signalNumber == signal.SIGINT:
            self.stop()

    def stop(self):
        if self._single:
            self.pipe.terminate()
        else:
            for p in self.__ps:
                p.join()
        for hook in self._stopHook:
            hook()

    def loop(self):
        signal.pause()

class ClbcClient(object):
    def __init__(self, server="pylcc.openanolis.cn", ver="", arch=""):
        super(ClbcClient, self).__init__()
        c = CexecCmd()
        if ver == "":
            ver = c.cmd('uname -r')
        if arch == "":
            arch = self._getArchitecture(c)
        self._server = server
        self._ver = ver
        self._arch = arch
        self._fastOff = False

    def _getArchitecture(self, c):
        lines = c.cmd('lscpu').split('\n')
        for line in lines:
            if line.startswith("Architecture"):
                arch = line.split(":", 1)[1].strip()
                if arch.startswith("arm"):
                    return "arm"
                return arch
        return "Unkown"

    def _setupSocket(self):
        addr = (self._server, LBC_COMPILE_PORT)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(addr)
        return s

    @staticmethod
    def _send_lbc(s, send):
        send = "LBC%08x" % (len(send)) + send
        s.send(send.encode())

    @staticmethod
    def _recv_lbc(s):
        if sys.version_info.major == 2:
            d = s.recv(LBCBuffSize)
        else:
            d = s.recv(LBCBuffSize).decode()
        if d[:3] != "LBC":
            return None
        size = d[3:11]
        try:
            size = int(size, 16) + 11
        except:
            raise DbException("bad lbc Exception, %s" % size)
        if size > LBCBuffSize:
            return None
        while len(d) < size:
            if sys.version_info.major == 2:
                d += s.recv(LBCBuffSize)
            else:
                d += s.recv(LBCBuffSize).decode()
        res = json.loads(d[11:])
        if res['log'] != "ok.":
            raise DbException('db set return %s' % res["log"])
        return res

    def getFunc(self, func, ret=None, arg=None):
        s = self._setupSocket()
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "func",
                 "func": func}
        if ret: dSend['ret'] = ret
        if arg: dSend['arg'] = arg
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getStruct(self, sStruct):
        s = self._setupSocket()
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "struct",
                 "struct": sStruct}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getType(self, t):
        s = self._setupSocket()
        if "*" in t:
            t = '_'
        dSend = {"arch": self._arch,
                 "ver": self._ver,
                 "cmd": "type",
                 "type": t}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

class CdbParser(object):
    def __init__(self, dbPath=""):
        super(CdbParser, self).__init__()
        if dbPath == "":
            c = CexecCmd()
            ver = c.cmd('uname -r')
            dbPath = "info-%s.db" % ver
        if not os.path.exists(dbPath):
            raise DbException("db %s is not exist." % dbPath)
        self._db = sqlite3.connect(dbPath)
        self._fastOff = False

    def _dbCheckArg(self, k, v):
        if ";" in v:
            return {"log": "bad %s key." % k}

    def _genFuncRet(self, cur, res):
        lR = []
        for r in res:
            args = json.loads(r[1])
            fid = r[4]
            sql = "SELECT file FROM files WHERE id = '%d'" % fid
            res = cur.execute(sql)
            txt = res.fetchone()[0]
            d = {"func": r[0], "args": args, "ret": r[2], "line": r[3], "file": txt}
            lR.append(d)
        return lR

    def _chekcFunfilter(self, func):
        if "%" not in func:
            raise ValueError("bad arg %s, args should contains %." % func)

    def _getFuncs(self, func, limit=20):
        self._chekcFunfilter(func)
        cur = self._db.cursor()
        sql = "SELECT func, args, ret, line, fid FROM funs WHERE func LIKE '%s' LIMIT %d" % (func, limit)
        res = cur.execute(sql).fetchall()
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def _getFunc(self, func):
        cur = self._db.cursor()
        sql = "SELECT func, args, ret, line, fid FROM funs WHERE func = '%s'" % func
        res = cur.execute(sql).fetchall()
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def _getFuncFilterRet(self, ret, func="", limit=100):
        cur = self._db.cursor()
        sql = "SELECT func, args, ret, line, fid FROM funs WHERE (ret = '%s' OR ret = 'static %s')" % (ret, ret)
        if func != "":
            self._chekcFunfilter(func)
            sql += " AND func LIKE '%s'" % func
        sql += " LIMIT %d" % limit
        res = cur.execute(sql)
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def _getFuncFilterArg(self, arg, func="", limit=100):
        cur = self._db.cursor()
        sql = "SELECT func, args, ret, line, fid FROM funs, json_each(funs.args) WHERE json_each.value = '%s'" % arg
        if func != "":
            self._chekcFunfilter(func)
            sql += " AND func LIKE '%s'" % func
        sql += " LIMIT %d" % limit
        res = cur.execute(sql)
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def __getStruct(self, cur, sStruct, limit=10):
        if '%' in sStruct:
            sql = "SELECT id, name, members, bytes FROM structs WHERE name LIKE '%s' LIMIT %d" % (sStruct, limit)
            res = cur.execute(sql)
            rDs = []
            for r in res.fetchall():
                rD = {"name": r[1], "members": r[2], "size": r[3]}
                rDs.append(rD)
            return rDs

        sql = "SELECT id, name, members, bytes FROM structs WHERE name = '%s'" % sStruct
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        fid = r[0]
        rD = {"name": r[1], "members": r[2], "size": r[3]}
        sql = "SELECT types, offset, bytes, bits, name FROM members WHERE fid = %d" % fid
        res = cur.execute(sql)
        cells = []
        for r in res.fetchall():
            dCell = {"type": r[0], "offset": r[1], "size": r[2],
                     "bits": r[3], "name": r[4]}
            cells.append(dCell)
        rD["cell"] = cells
        return rD

    def _getStruct(self, sStruct):
        cur = self._db.cursor()
        r = self.__getStruct(cur, sStruct)
        cur.close()
        return r

    def _getType(self, t):
        cur = self._db.cursor()
        if '*' not in t:
            sql = "SELECT name, alias, bytes FROM types WHERE name = '%s'" % t
        else:
            sql = "SELECT name, alias, bytes FROM types WHERE id = 1"
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        return {"name": r[0], "type": r[1], "size": r[2]}

    def getFunc(self, func, ret=None, arg=None):
        dSend = {"log": "ok."}
        if ret is not None:
            r = self._dbCheckArg("ret", ret)
            if r: return r
            try:
                dSend['res'] = self._getFuncFilterRet(ret, func)
                return dSend
            except ValueError:
                return {"log": "query value error."}
        if arg is not None:
            r = self._dbCheckArg("arg", arg)
            if r: return r
            try:
                dSend['res'] = self._getFuncFilterArg(arg, func)
                return dSend
            except ValueError:
                return {"log": "query value error."}
        if "%" in func:
            dSend['res'] = self._getFuncs(func)
        else:
            dSend['res'] = self._getFunc(func)
        return dSend

    def getStruct(self, sStruct):
        dSend = {"log": "ok."}
        dSend['res'] = self._getStruct(sStruct)
        return dSend

    def getType(self, t):
        dSend = {"log": "ok."}
        dSend['res'] = self._getType(t)
        return dSend

class CgdbParser(object):
    def __init__(self, vmlinuxPath="", gdb=None):
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
                beg = res[0];
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

class surftrace(ftrace):
    def __init__(self, args, parser, show=False, echo=True, arch="", stack=False, cb=None, cbOrig=None, cbShow=None):
        super(surftrace, self).__init__(show=show, echo=echo)
        self._parser = parser
        self._probes = []
        self._events = []
        if not self._show:
            self._checkIsEmpty()
        self._arch = arch
        if self._arch == "":
            self._arch = self._getArchitecture()
        self._args = args
        self._stack = stack
        if isinstance(args, list):
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
            self._func = None

        self._cb = cb
        self._cbOrig = cbOrig

        if cbShow: self._cbShow = cbShow
        else: self._cbShow = self._showFxpr

    def _getArchitecture(self):
        lines = self._c.cmd('lscpu').split('\n')
        for line in lines:
            if line.startswith("Architecture"):
                arch = line.split(":", 1)[1].strip()
                if arch.startswith("arm"):
                    return "arm"
                if arch.startswith('x86'):
                    return "x86"
                return arch
        return "Unkown"

    def _clearProbes(self):
        if self._show:
            return
        for p in self._probes:
            fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/" + p + "/enable"
            self._echoPath(fPath, "0")
            cmd = '-:%s' % p
            self._echoDPath(self.baseDir + "/tracing/kprobe_events", cmd)
        self._probes = []
        for ePath in self._events:
            self._echoPath(ePath, "0")
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
        eBase = os.path.join(self.baseDir, "tracing/instances/surftrace/events")
        eDir = os.path.join(eBase, e)
        if not os.path.exists(eDir):
            raise InvalidArgsException("event %s is not an available event, see %s" % (e, eBase))
        if res['filter'] != "":
            filter = res['filter']
            try:
                filter = self.__checkFilter(filter)
            except Exception as e:
                if self._echo: print(e.message)
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
            self._events.append(ePath)

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
            if c in ('.', '-'):
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
                indexMax = int(self._reSquareBrackets.findall(name)[0])
                name = name.split("[")[0]
            if name == member:
                if add > 0:
                    if add >= indexMax:
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
                argi = regIndex(reg, self._arch)
            if types == '':
                argt = self._func['args'][argi]
            else:
                argt = types
            regArch = transReg(argi, self._arch)
        else:
            types, xpr = expr.split('$retval')
            if types == '':
                argt = self._func['ret']
            else:
                argt = types
            regArch = '$retval'
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
    
    def _cellCheck(self, cells, reg):
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
        self._fxprAddSuffix(lastCell)
        return lastCell
            
    def _checkExpr(self, e):
        self.__checkBegExpr(e)
        self.__checkFormat(e)

        showType, reg, argt, xpr = self.__getExprArgi(e)

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

        func = symbol
        if "+" in func:
            func = func.split("+", 1)[0]
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
            self._checkExpr(expr)
            var, _ = expr.split("=", 1)
            if var in vars:
                raise ExprException("var %s is already used at previous expression" % var)
            vars.append(var)
            cmd += " %s=" % var + self._strFxpr
        if not self._show:
            self._echoDPath(self.baseDir + "/tracing/kprobe_events", "'" + cmd + "'")
            self._probes.append(name)
        if res['filter'] != "":
            try:
                filter = self.__checkFilter(res['filter'])
            except Exception as e:
                if self._echo: print(e.message)
                raise InvalidArgsException('bad filter：%s' % res['filter'])
            if self._show:
                self.__showExpression(res['type'], cmd, filter)
            else:
                fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/%s/filter" % name
                self._echoFilter(fPath, "'%s'" % filter)
                fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/" + name + "/enable"
                self._echoPath(fPath, "1")
        else:
            if self._show:
                self.__showExpression(res['type'], cmd)
            else:
                fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/" + name + "/enable"
                self._echoPath(fPath, "1")

    def _setupStack(self):
        fPath = self.baseDir + "/tracing/instances/surftrace/options/stacktrace"
        if not os.path.exists(fPath):
            fPath = self.baseDir + "/tracing/options/stacktrace"
        if self._stack:
            self._events.append(fPath)
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

    def _checkIsEmpty(self):
        if not os.path.exists(self.baseDir + '/tracing/instances/' + 'surftrace'):
            os.mkdir(self.baseDir + '/tracing/instances/' + 'surftrace')
        return
        cmd = 'cat %s/tracing/kprobe_events' % (self.baseDir)
        line = self._c.cmd(cmd).strip()
        if line != "":
            raise FileNotEmptyException("kprobe_events is not empty. should clear other kprobe at first.")

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
            fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/%s/filter" % resFxpr['name']
            self._echoFilter(fPath, "'%s'" % res['filter'])

        fPath = self.baseDir + "/tracing/instances/surftrace/events/kprobes/" + resFxpr['name'] + "/enable"
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
            if self._cbOrig:
                self.pipe.newCb(self._cbOrig)
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
        if arch not in ('x86', 'x86_64', 'aarch64'):
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
