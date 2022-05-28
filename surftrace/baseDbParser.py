# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     baseDbParser.py
   Description :
   Author :       liaozhaoyan
   date：          2022/5/28
-------------------------------------------------
   Change Activity:
                   2022/5/28:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import json
import sqlite3

from .baseParser import CbaseParser
from .surfException import DbException


class CbaseDbParser(CbaseParser):
    def __init__(self, dbPath):
        super(CbaseDbParser, self).__init__()
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
            if r:
                return r
            try:
                dSend['res'] = self._getFuncFilterRet(ret, func)
                return dSend
            except ValueError:
                return {"log": "query value error."}
        if arg is not None:
            r = self._dbCheckArg("arg", arg)
            if r:
                return r
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
        dSend = {"log": "ok.", 'res': self._getStruct(sStruct)}
        return dSend

    def getType(self, t):
        dSend = {"log": "ok.", 'res': self._getType(t)}
        return dSend

if __name__ == "__main__":
    pass
