# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfDwarf
   Description :
   Author :       liaozhaoyan
   date：          2022/11/3
-------------------------------------------------
   Change Activity:
                   2022/11/3:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import os
import ctypes as ct
import json
import sqlite3


def getCwd(pathStr):
    return os.path.split(os.path.realpath(pathStr))[0]


class CelfBase(object):
    def __init__(self):
        super(CelfBase, self).__init__()
        soPath = os.path.join(getCwd(__file__), "dwarf_walk.so")
        if not os.path.exists(soPath):
            self._downSo(soPath)
        self._so = ct.CDLL(soPath)
        self._dlsym()

    def _downSo(self, soPath):
        pass

    def __del__(self):
        if hasattr(self, "_so"):
            del self._so

    def _dlsym(self):
        pass


class CdwarfBase(CelfBase):
    def __init__(self, path):
        super(CdwarfBase, self).__init__()
        self._path = os.path.abspath(path)
        self._handler = self._so.dwarf_load(path)
        if self._handler is None:
            raise ValueError("load %s failed" % path)

    def __del__(self):
        if hasattr(self, "_handler") and self._handler is not None:
            self._so.dwarf_close(self._handler)
        super(CdwarfBase, self).__del__()

    def _dlsym(self):
        self._showCallback = ct.CFUNCTYPE(ct.c_int, ct.c_char_p)
        self._filterCallback = ct.CFUNCTYPE(ct.c_int, ct.c_char_p)

        self._so.dwarf_load.restype = ct.c_void_p
        self._so.dwarf_load.argtypes = [ct.c_char_p]
        self._so.dwarf_close.argtypes = [ct.c_void_p]
        self._so.dwarf_show.restype = ct.c_int
        self._so.dwarf_show.argtypes = [ct.c_void_p]
        self._so.dwarf_walk_compile_unit.restype = ct.c_int
        self._so.dwarf_walk_compile_unit.argtypes = [ct.c_void_p, self._showCallback]
        self._so.dwarf_walk2json.restype = ct.c_int
        self._so.dwarf_walk2json.argtypes = [ct.c_void_p, self._showCallback]
        self._so.dwarf_filter2json.restype = ct.c_int
        self._so.dwarf_filter2json.argtypes = [ct.c_void_p, self._showCallback, self._filterCallback]

    def show(self):
        self._so.dwarf_show(self._handler)

    def _units(self, cb):
        f = self._showCallback(cb)
        self._so.dwarf_walk_compile_unit(self._handler, f)

    def _walks(self, cb):
        f = self._showCallback(cb)
        self._so.dwarf_walk2json(self._handler, f)

    def units(self):
        arr = []

        def _cb(s):
            arr.append(s)
            return 0

        self._units(_cb)
        return arr

    def walks(self):
        def _cb(s):
            obj = json.loads(s)
            print(obj)
            return 0

        self._walks(_cb)


class CdwarfDb(CdwarfBase):
    def __init__(self, path, db):
        super(CdwarfDb, self).__init__(path)
        self._db = self._setupDb(db)
        self._offD = {}
        self._filePath = ""
        self._fileId = -1
        self._cur = None

        self._cbs = {
            "DW_TAG_base_type": self._cb_base_type,
            "DW_TAG_pointer_type": self._cb_point_type,
            "DW_TAG_typedef": self._cb_typedef,
            "DW_TAG_subprogram": self._cb_subprogram,
            "DW_TAG_structure_type": self._cb_structure,
            "DW_TAG_union_type": self._cb_union,
            "DW_TAG_enumeration_type": self._cb_enumeration,
        }

    def __del__(self):
        if hasattr(self, "_db") and self._db is not None:
            self._db.close()
        super(CdwarfDb, self).__del__()

    def _setupDb(self, dbPath):
        if os.path.exists(dbPath):
            db = sqlite3.connect(dbPath)
            return db
        db = sqlite3.connect(dbPath)
        cur = db.cursor()
        sqls = [
            """CREATE TABLE files ( 
                                      id INTEGER PRIMARY KEY autoincrement,
                                      file TEXT
                            );""",
            """CREATE TABLE funs ( 
                              id INTEGER PRIMARY KEY autoincrement,
                              func VARCHAR (128),
                              args VARCHAR (256),
                              argi VARCHAR (256),
                              ret VARCHAR (64),
                              line INTEGER,
                              fid INTEGER, 
                              module VARCHAR (64)
                    );""",
            """CREATE TABLE structs ( 
                                      id INTEGER PRIMARY KEY autoincrement,
                                      name VARCHAR (64),
                                      members INTEGER,
                                      bytes INTEGER
                            );""",
            """CREATE TABLE members ( 
                                              id INTEGER PRIMARY KEY autoincrement,
                                              fid INTEGER,
                                              types VARCHAR (128),
                                              name VARCHAR (64),
                                              offset INTEGER,
                                              bytes INTEGER,
                                              bits VARCHAR (16) DEFAULT ""
                                    );""",
            """CREATE TABLE types ( 
                                              id INTEGER PRIMARY KEY autoincrement,
                                              name VARCHAR (64),
                                              alias VARCHAR (64),
                                              bytes INTEGER
                                    );""",
        ]
        for sql in sqls:
            cur.execute(sql)
        cur.close()
        return db

    def _type_is_in(self, t):
        sql = "SELECT name FROM types WHERE name = '%s'" % t
        res = self._cur.execute(sql)
        if res is None:
            return False
        r = res.fetchone()
        if r is None:
            return False
        return True

    def _save_type(self, name, alias, size):
        sql = 'INSERT INTO types (name, alias, bytes) VALUES ("%s", "%s", %d)' % (
            name, alias, size
        )
        self._cur.execute(sql)

    def _save_file(self, fileName):
        sql = '''INSERT INTO files (file) VALUES ("%s")''' % fileName
        self._cur.execute(sql)
        return self._cur.lastrowid

    def _get_ref_array(self, cell):
        res = ""
        for child in cell["child"]:
            if "DW_AT_upper_bound" in child:
                res += "[%d]" % (child["DW_AT_upper_bound"] + 1)
            else:
                res += "[%d]" % 1
        return res

    def _get_array_scale(self, cell):
        scale = 1
        for child in cell["child"]:
            if "DW_AT_upper_bound" in child:
                scale *= child["DW_AT_upper_bound"] + 1
        return scale

    def _get_pfunc(self, cell):
        if "DW_AT_type" in cell:
            resId = cell['DW_AT_type']
            resCell = self._offD[resId]
            res = self._get_ref_type(resCell)
        else:
            res = "void"

        if "child" in cell:
            args = []
            for child in cell["child"]:
                if "DW_AT_type" in child:
                    resId = child['DW_AT_type']
                    resCell = self._offD[resId]
                    args.append(self._get_ref_type(resCell))
                else:
                    args = ["void"]
                    break
        else:
            args = ['void']

        return "%s (*)(%s)" % (res, ", ".join(args))

    def _get_ref_type(self, cell):
        aType = cell["tag_name"]
        tHeads = {
            "DW_TAG_structure_type": "struct",
            "DW_TAG_union_type": "union",
            "DW_TAG_enumeration_type": "enum",
        }
        if aType in ("DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type"):
            if "DW_AT_name" in cell:
                return " ".join((tHeads[aType], cell["DW_AT_name"]))
            else:
                return tHeads[aType]
        elif aType == "DW_TAG_base_type":
            return cell["DW_AT_name"]
        elif aType == "DW_TAG_pointer_type":
            if 'DW_AT_type' in cell:
                resId = cell['DW_AT_type']
                resCell = self._offD[resId]
                if resCell["tag_name"] == "DW_TAG_subroutine_type":
                    return self._get_pfunc(resCell)
                return self._get_ref_type(resCell) + "*"
            return "void*"
        elif aType == "DW_TAG_array_type":
            resId = cell['DW_AT_type']
            resCell = self._offD[resId]
            return self._get_ref_type(resCell) + self._get_ref_array(cell)
        elif aType in ("DW_TAG_formal_parameter", "DW_TAG_typedef", "DW_TAG_member"):
            resId = cell['DW_AT_type']
            resCell = self._offD[resId]
            return self._get_ref_type(resCell)
        return aType

    def _get_ref_size(self, cell):
        scale = 1
        while "DW_AT_byte_size" not in cell:
            if cell["tag_name"] == "DW_TAG_array_type":
                scale = self._get_array_scale(cell)
            if "DW_AT_type" in cell:
                resId = cell['DW_AT_type']
                cell = self._offD[resId]
            else:
                return 8 * scale
        return cell["DW_AT_byte_size"] * scale

    def _get_func_args(self, childs):
        args = []
        argi = []
        for cell in childs:
            aType = cell["tag_name"]
            if aType == "DW_TAG_formal_parameter":
                args.append(self._get_ref_type(cell))
                argi.append(cell['DW_AT_name'])
        return args, argi

    def _cb_subprogram(self, cell):
        if "DW_AT_name" not in cell:
            return
        name = cell['DW_AT_name']
        if "DW_AT_decl_line" in cell:
            line = cell['DW_AT_decl_line']
        else:
            line = 0

        if "DW_AT_type" in cell:
            resId = cell['DW_AT_type']
            resCell = self._offD[resId]
            retType = self._get_ref_type(resCell)
        else:
            retType = "void"

        if "child" in cell:
            args, argi = self._get_func_args(cell['child'])
        else:
            args = ["void"]
            argi = []

        sql = '''INSERT INTO funs (func, args, argi, ret, line, fid, module) VALUES \
                    ("%s", ?, ?, "%s", %d, %d, "%s")''' % (
            name, retType, line, self._fileId, self._path)
        self._cur.execute(sql, (json.dumps(args), json.dumps(argi)))

    def _save_type1(self, cell, name, alias=""):
        if not self._type_is_in(name):
            if alias == "":
                alias = name
            size = self._get_ref_size(cell)
            self._save_type(name, alias, size)

    def _cb_base_type(self, cell):
        self._save_type1(cell, cell['DW_AT_name'])

    def _cb_point_type(self, cell):
        self._save_type1(cell, "void *")

    def _cb_typedef(self, cell):
        name = cell["DW_AT_name"]
        resId = cell['DW_AT_type']
        resCell = self._offD[resId]
        while resCell["tag_name"] == "DW_TAG_typedef":
            resId = resCell['DW_AT_type']
            resCell = self._offD[resId]
        alias = self._get_ref_type(resCell)
        self._save_type1(resCell, name, alias)

    def _struct_is_in(self, sStruct):
        sql = "SELECT name FROM structs WHERE name = '%s'" % sStruct
        res = self._cur.execute(sql)
        if res is None:
            return False
        r = res.fetchone()
        if r is None:
            return False
        return True

    def _member_bits(self, cell):
        res = ""
        if "DW_AT_bit_offset" in cell:
            size = cell["DW_AT_bit_size"]
            offset = 8 * cell["DW_AT_byte_size"] - cell["DW_AT_bit_offset"] - size
            res = "%d:%d" % (offset, size)
        return res

    def _save_member(self, cell, fid, offset):
        name = cell["DW_AT_name"]
        types = self._get_ref_type(cell)
        size = self._get_ref_size(cell)
        bits = self._member_bits(cell)
        sql = "INSERT INTO members (fid, types, name, offset, bytes, bits) "
        sql += 'VALUES (%d, "%s", "%s", %d, %d, "%s")' % (fid, types, name, offset, size, bits)
        self._cur.execute(sql)

    def _anony_struct(self, cell, fid, beg):
        isStruct = cell['tag_name'] == "DW_TAG_structure_type"
        for cell in cell["child"]:
            if isStruct:
                offset = beg + cell["DW_AT_data_member_location"]
            else:
                offset = beg
            if "DW_AT_name" in cell:
                self._save_member(cell, fid, offset)
            else:
                resId = cell['DW_AT_type']
                resCell = self._offD[resId]
                self._anony_struct(resCell, fid, offset)

    def _save_struct(self, cell, sStruct):
        if "DW_AT_byte_size" not in cell:
            return
        size = cell["DW_AT_byte_size"]
        if size > 0:
            nums = len(cell["child"])
            sql = 'INSERT INTO structs (name, members, bytes) '
            sql += 'VALUES ("%s", %d, %d)' % (sStruct, nums, size)
            self._cur.execute(sql)
            fid = self._cur.lastrowid

            isStruct = cell['tag_name'] == "DW_TAG_structure_type"
            for cell in cell["child"]:
                if isStruct:
                    offset = cell["DW_AT_data_member_location"]
                else:
                    offset = 0

                if "DW_AT_name" in cell:
                    self._save_member(cell, fid, offset)
                else:  # for anony struct or union
                    resId = cell['DW_AT_type']
                    resCell = self._offD[resId]
                    self._anony_struct(resCell, fid, offset)
        else:
            nums = 0
            sql = 'INSERT INTO structs (name, members, bytes) '
            sql += 'VALUES ("%s", %d, %d)' % (sStruct, nums, size)
            self._cur.execute(sql)

    def _cb_structure(self, cell):
        if "DW_AT_name" in cell:
            sStruct = "struct " + cell["DW_AT_name"]
            if not self._struct_is_in(sStruct):
                self._save_struct(cell, sStruct)

    def _cb_union(self, cell):
        if "DW_AT_name" in cell:
            sStruct = "union " + cell["DW_AT_name"]
            if not self._struct_is_in(sStruct):
                self._save_struct(cell, sStruct)

    def _cb_enumeration(self, cell):
        if "DW_AT_name" in cell:
            sStruct = "enum " + cell["DW_AT_name"]
            if not self._struct_is_in(sStruct):
                if "DW_AT_byte_size" in cell:
                    size = cell["DW_AT_byte_size"]
                    nums = len(cell["child"])
                    sql = 'INSERT INTO structs (name, members, bytes) '
                    sql += 'VALUES ("%s", %d, %d)' % (sStruct, nums, size)
                    self._cur.execute(sql)

    def _walk_offs(self, cells):
        for cell in cells:
            self._offD[cell['offset']] = cell
            if "child" in cell:
                self._walk_offs(cell["child"])

    def _splitCells(self, cells):
        for cell in cells:
            tag = cell["tag_name"]
            if tag in self._cbs.keys():
                self._cbs[tag](cell)

    def _toDb(self, dElf):
        topD = dElf['child'][0]
        if topD["tag_name"] != "DW_TAG_compile_unit":
            raise ValueError("top dict tag name is %s, not DW_TAG_compile_unit" %
                             topD["tag_name"])

        self._offD[topD['offset']] = topD
        path = topD["DW_AT_comp_dir"]
        name = topD["DW_AT_name"]
        self._filePath = os.path.join(path, name)
        print(self._filePath)
        self._fileId = self._save_file(self._filePath)
        if "child" in topD:
            self._walk_offs(topD["child"])
            self._splitCells(topD["child"])

        self._offD = {}

    def walks(self):
        self._cur = self._db.cursor()

        def _cb(s):
            with open("vm.json", "w") as f:
                f.write(s)
            obj = json.loads(s)
            self._toDb(obj)
            global loop
            loop += 1
            if loop > 5:
                return 1
            else:
                loop += 1
                return 0

        self._walks(_cb)
        self._cur.close()
        self._db.commit()

loop = 0

if __name__ == "__main__":
    # scp -P 2201 root@100.82.20.22:/root/1ext/code/surftrace/tools/dwarf/walks/local.db ./
    d = CdwarfDb("samelf/samelf", "local.db")
    d.walks()
    pass
