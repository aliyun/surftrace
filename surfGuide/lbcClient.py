# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     lbcClient
   Description :
   Author :       liaozhaoyan
   date：          2021/12/4
-------------------------------------------------
   Change Activity:
                   2021/12/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
sys.path.append("../")
import socket
import json
import os
import sqlite3
from surftrace import CexecCmd


LBC_COMPILE_PORT = 7654
LBCBuffSize = 80 * 1024 * 1024

class DbException(Exception):
    def __init__(self, message):
        super(DbException, self).__init__(message)
        self.message = message

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
        d = s.recv(LBCBuffSize).decode("utf-8")
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
            d += s.recv(LBCBuffSize).decode("utf-8")
        res = json.loads(d[11:])
        if res['log'] != "ok.":
            raise DbException('db set return %s' % res["log"])
        return res

    def getFunc(self, func, ret=None, arg=None):
        s = self._setupSocket()
        dSend = {"ver": self._ver,
                 "cmd": "func",
                 "func": func}
        if ret: dSend['ret'] = ret
        if arg: dSend['arg'] = arg
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getStruct(self, sStruct):
        s = self._setupSocket()
        dSend = {"ver": self._ver,
                 "cmd": "struct",
                 "struct": sStruct}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

    def getType(self, t):
        s = self._setupSocket()
        if "*" in t:
            t = '_'
        dSend = {"ver": self._ver,
                 "cmd": "type",
                 "type": t}
        self._send_lbc(s, json.dumps(dSend))
        return self._recv_lbc(s)

class CdbParser(object):
    def __init__(self, dbPath):
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

if __name__ == "__main__":
    c = ClbcClient(ver="4.9.168-016.ali3000.alios7.x86_64")
    print(c.getFunc("ip_local_deliver"))
    print(c.getStructs("struct sock_common"))
    print(c.getType("atomic_t"))

    c = CdbParser("info-4.9.168-016.ali3000.alios7.x86_64.db")
    print(c.getFunc("ip_local_deliver"))
    print(c.getStruct("struct sock_common"))
    print(c.getType("atomic_t"))
