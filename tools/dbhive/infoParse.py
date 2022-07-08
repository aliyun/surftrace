# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     infoParse
   Description :
   Author :       liaozhaoyan
   date：          2021/12/3
-------------------------------------------------
   Change Activity:
                   2021/12/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os.path
import sqlite3
import json

class CinfoParse(object):
    def __init__(self, dbPath):
        if not os.path.exists(dbPath):
            raise IOError(f"db {dbPath} is not exist.")
        self._db = sqlite3.connect(dbPath, uri=True)

    def __del__(self):
        if self._db is not None:
            self._db.commit()
            self._db.close()

    def _genFuncRet(self, cur, res):
        lR = []
        for r in res:
            args = json.loads(r[1])
            fid = r[4]
            sql = f"SELECT file FROM files WHERE id = '{fid}'"
            res = cur.execute(sql)
            txt = res.fetchone()[0]
            d = {"func": r[0], "args": args, "ret": r[2], "line": r[3], "file": txt}
            lR.append(d)
        return lR

    def getFunc(self, func):
        cur = self._db.cursor()
        sql = f"SELECT func, args, ret, line, fid FROM funs WHERE func = '{func}'"
        res = cur.execute(sql).fetchall()
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def _chekcFunfilter(self, func):
        if "%" not in func:
            raise ValueError(f"bad arg {func}, args should contains %.")

    def getFuncs(self, func, limit=20):
        self._chekcFunfilter(func)
        cur = self._db.cursor()
        sql = f"SELECT func, args, ret, line, fid FROM funs WHERE func LIKE '{func}' LIMIT {limit}"
        res = cur.execute(sql).fetchall()
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def getFuncFilterRet(self, ret, func="", limit=100):
        cur = self._db.cursor()
        sql = f"SELECT func, args, ret, line, fid FROM funs WHERE (ret = '{ret}' OR ret = 'static {ret}')"
        if func != "":
            self._chekcFunfilter(func)
            sql += f" AND func LIKE '{func}'"
        sql += f" LIMIT {limit}"
        res = cur.execute(sql)
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def getFuncFilterArg(self, arg, func="", limit=100):
        cur = self._db.cursor()
        sql = f"SELECT func, args, ret, line, fid FROM funs, json_each(funs.args) WHERE json_each.value = '{arg}'"
        if func != "":
            self._chekcFunfilter(func)
            sql += f" AND func LIKE '{func}'"
        sql += f" LIMIT {limit}"
        res = cur.execute(sql)
        lR = self._genFuncRet(cur, res)
        cur.close()
        return lR

    def _getStruct(self, cur, struct, limit=10):
        if '%' in struct:
            sql = f"SELECT id, name, members, bytes FROM structs WHERE name LIKE '{struct}' LIMIT {limit}"
            res = cur.execute(sql)
            rDs = []
            for r in res.fetchall():
                rD = {"name": r[1], "members": r[2], "size": r[3]}
                rDs.append(rD)
            return rDs

        sql = f"SELECT id, name, members, bytes FROM structs WHERE name = '{struct}'"
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        fid = r[0]
        rD = {"name": r[1], "members": r[2], "size": r[3]}
        sql = f"SELECT types, offset, bytes, bits, name FROM members WHERE fid = {fid}"
        res = cur.execute(sql)
        cells = []
        for r in res.fetchall():
            dCell = {"type": r[0], "offset": r[1], "size": r[2],
                     "bits": r[3], "name": r[4]}
            cells.append(dCell)
        rD["cell"] = cells
        return rD

    def getStruct(self, struct):
        cur = self._db.cursor()
        r = self._getStruct(cur, struct)
        cur.close()
        return r

    def _getStructMember(self, cur, struct, memeber):
        sql = f"SELECT id FROM structs WHERE name = '{struct}'"
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        fid = r[0]
        sql = f"SELECT types, offset, bytes, bits, name FROM members WHERE fid = {fid} \
                AND (name = '{memeber}' OR name LIKE '{memeber}[%]')"
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        rD = {"type": r[0], "offset": r[1], "size": r[2], "bits": r[3], "name": r[4]}
        return rD

    def getStructMember(self, struct, memeber):
        cur = self._db.cursor()
        r = self._getStructMember(cur,struct, memeber)
        cur.close()
        return r

    def getType(self, t):
        cur = self._db.cursor()
        sql = f"SELECT name, alias, bytes FROM types WHERE name = '{t}'"
        res = cur.execute(sql)
        r = res.fetchone()
        if r is None: return None
        return {"name": r[0], "type": r[1], "size": r[2]}

if __name__ == "__main__":
    i = CinfoParse("info-3.10.0-327.ali2013.1.alios7.x86_64.db")
    print(i.getStructMember("struct sock", "sk_backlog.head"))
    print(i.getFunc("set_in_cr4"))
    print(i.getStruct("struct sock"))
    print(i.getFuncFilterArg("int", func="skb%"))
    print(i.getType("u_int8"))
