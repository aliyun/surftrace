# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     symDb
   Description :
   Author :       liaozhaoyan
   date：          2022/12/6
-------------------------------------------------
   Change Activity:
                   2022/12/6:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sqlite3


class CsymDb(object):
    def __init__(self, db):
        super(CsymDb, self).__init__()
        self._max = 2 ** 63 - 1     # sqlite only support signed long
        self._db = self._setupDb(db)

    def _setupDb(self, dbPath):
        db = sqlite3.connect(dbPath)
        db.execute("PRAGMA journal_mode = MEMORY")
        db.execute("PRAGMA synchronous = OFF")
        cur = db.cursor()
        sqls = [
            """CREATE TABLE ksyms ( 
                                id INTEGER PRIMARY KEY autoincrement,
                                addr UNSIGNED BIG INT,
                                t VARCHAR (1),
                                sym VARCHAR (64),
                                mod VARCHAR (32)
                                );""",
            """CREATE INDEX "iaddr" ON "ksyms" ( "addr" ASC );""",
        ]
        for sql in sqls:
            cur.execute(sql)
        cur.close()
        db.commit()
        return db

    def transAddr(self, addr):

    def ksym(self):
        cur = self._db.cursor()
        cur.execute("BEGIN TRANSACTION")
        with open("/proc/kallsyms", 'r') as f:
            for line in f.readlines():
                line = line.rstrip('\n')
                cells = line.split(' ')
                sql = 'INSERT INTO ksyms (addr, t, sym, mod) '
                addr = int("0x" + cells[0], 16)
                if addr > self._max:
                    addr -= self._max
                if '\t' in cells[2]:
                    sym, mod = cells[2].split("\t")
                    sql += 'VALUES (%d, "%s", "%s", "%s")' % (addr, cells[1], sym, mod)
                else:
                    sql += 'VALUES (%d, "%s", "%s", "")' % (addr, cells[1], cells[2])
                cur.execute(sql)
        cur.close()
        self._db.commit()

    def querySym(self, addr):

        sql = "SELECT addr, t, sym, mod FROM ksyms WHERE addr >= %d ORDER BY addr LIMIT 1" % addr
        res = self._db.execute(sql)
        r = res.fetchone()
        print("0x%x" % addr)
        print("0x%x" % r[0])
        print(r)
        print(r[0] - addr)


if __name__ == "__main__":
    k = CsymDb("local.db")
    k.ksym()
    k.querySym(0xffffffffc0252ee0)
    pass
