# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     lbcMaps
   Description :
   Author :       liaozhaoyan
   date：          2021/7/20
-------------------------------------------------
   Change Activity:
                   2021/7/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import ctypes as ct
import struct
from surftrace.surfElf import CstructKsym
from sys import version_info

try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from surftrace import InvalidArgsException
from surftrace.surfCommon import CsurfList


class CtypeData(object):
    def __init__(self, dForm, data):
        super(CtypeData, self).__init__()
        self.dForm = dForm
        self._initData(data)

    def _invData(self, v, dFormat):
        # if dFormat.has_key('format'):  not support for python3
        if 'format' in dFormat:
            if dFormat['array']:
                data = None
                for c in v:
                    data += struct.pack("%s" % dFormat['format'][0], c)
            else:
                data = struct.pack("%s" % dFormat['format'], v)
        else:
            data = None
            for d in dFormat['cells']:
                data += self._invData(v[d['member']], d)
        return data

    @staticmethod
    def __strlen(stream, size):
        for i in range(size):
            if stream[i] == '\0':
                return i
        return i

    def _loadData(self, data, start, dFormat):
        if "format" in dFormat:
            if dFormat['array'] > 0:
                if dFormat['format'][0] == 'c':
                    stream = data[start:start + dFormat['size'] * dFormat['array']]
                    size = self.__strlen(stream, dFormat['array'])
                    tp = struct.unpack("%ds" % size, stream[:size])[0]
                    s = ''
                    if version_info.major == 2:
                        s = ''.join(tp)
                    else:
                        for t in tp:
                            if t != 0:
                                s += chr(t)
                            else:
                                break
                    return s
                else:
                    return struct.unpack(dFormat['format'].encode('utf-8'),
                                         data[start:start + dFormat['size'] * dFormat['array']])
            else:
                return struct.unpack(dFormat['format'].encode('utf-8'), data[start:start + dFormat['size']])[0]
        else:
            rDict = {}
            for d in dFormat['cells']:
                beg = start + d['offset']
                rDict[d['member']] = self._loadData(data[beg:], start, d)
            return rDict

    def _initData(self, data):
        if "format" in self.dForm:
            d = {'value': self._loadData(data, 0, self.dForm)}
        else:
            d = self._loadData(data, 0, self.dForm)
        self.localDict = d
        self.__dict__.update(self.localDict)


class CtypeTable(object):
    def __init__(self, fType, ffi):
        super(CtypeTable, self).__init__()
        self._type = fType
        self._ffiType = self._setupFfi(self._type)
        self._ffi = ffi

        self._localData = []

    @staticmethod
    def _setupFfi(s):
        if s.endswith("]"):
            return s
        else:
            return s + " *"

    def add(self, data):
        self._localData.append(self.load(data))

    def clear(self):
        self._localData = []

    def output(self):
        return self._localData

    def input(self, k):
        print(k)
        data = struct.pack("i", k)
        # size = self._ffi.sizeof("%s" % self._type)
        # v = self._ffi.new("%s *" % self._type, k)
        # pv = self._ffi.cast("char *", v)
        # data = struct.pack("c%d" % size, self._ffi.string(pv, size))
        return data

    def load(self, data):
        print(data)
        print(ct.POINTER(data))
        return self._ffi.cast(self._ffiType, ct.POINTER(data))


class CeventBase(object):
    def __init__(self, so, name):
        self._so = so
        self._id = self._so.lbc_bpf_get_maps_id(ct.c_char_p(name.encode('utf-8')))
        if self._id < 0:
            raise InvalidArgsException("map %s, not such event" % name)
        self.name = name
        super(CeventBase, self).__init__()


class CtableBase(CeventBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CtableBase, self).__init__(so, name)
        self._ffi = ffi
        self._kd = dTypes['fktype']
        self._vd = dTypes['fvtype']
        self.keys = CtypeTable(self._kd, ffi)
        self.values = CtypeTable(self._vd, ffi)

    def _getSize(self, fType):
        return self._ffi.sizeof(fType)

    def get(self):
        ksize = self._getSize(self._kd)
        vsize = self._getSize(self._vd)

        self.keys.clear()
        self.values.clear()
        v = ct.create_string_buffer(vsize)
        k1 = ct.create_string_buffer(ksize)
        k2 = ct.create_string_buffer(ksize)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            self._so.lbc_map_lookup_elem(self._id, k2, v)
            self.values.add(v)
            ct.memmove(k1, k2, ksize)
        return dict(zip(self.keys.output(), self.values.output()))

    def getThenClear(self):
        ksize = self._getSize(self._kd)
        vsize = self._getSize(self._vd)

        self.keys.clear()
        self.values.clear()
        v = ct.create_string_buffer(vsize)
        k1 = ct.create_string_buffer(ksize)
        k2 = ct.create_string_buffer(ksize)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            r = self._so.lbc_map_lookup_and_delete_elem(self._id, k2, v)
            if r < 0:
                raise InvalidArgsException(
                    "lbc_map_lookup_and_delete_elem return %d, os may not support this opertation." % r)
            self.values.add(v)
            ct.memmove(k1, k2, ksize)
        r = dict(zip(self.keys.output(), self.values.output()))
        return r

    def getKeys(self):
        self.keys.clear()
        self.values.clear()
        ksize = self._getSize(self._kd)

        k1 = ct.create_string_buffer(ksize)
        k2 = ct.create_string_buffer(ksize)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            ct.memmove(k1, k2, ksize)
        return self.keys.output()

    def getKeyValue(self, k):
        vsize = self._getSize(self._vd)
        key = self.keys.input(k)
        v = ct.create_string_buffer(vsize)
        print(key, vsize)
        if self._so.lbc_map_lookup_elem(self._id, key, v) == 0:
            return self.values.load(v)
        return None

    def clear(self):
        ksize = self._kd['size']
        k1 = ct.create_string_buffer(ksize)
        k2 = ct.create_string_buffer(ksize)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self._so.lbc_map_delete_elem(self._id, k2)
            ct.memmove(k1, k2, ksize)


class CmapsHash(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsHash, self).__init__(so, name, dTypes, ffi)


class CmapsArray(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsArray, self).__init__(so, name, dTypes, ffi)

    def get(self, size=10):
        a = []
        for i in range(size):
            a.append(self.getKeyValue(i))
        return a


class CmapsHist2(CmapsArray):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsHist2, self).__init__(so, name, dTypes, ffi)

    def get(self, size=64):
        return super(CmapsHist2, self).get(size)

    def showHist(self, head="dummy", array=None):
        if array is None:
            array = self.get()
        aList = CsurfList(1)
        print(head)
        aList.hist2Show(array)


class CmapsHist10(CmapsArray):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsHist10, self).__init__(so, name, dTypes, ffi)

    def get(self, size=20):
        return super(CmapsHist10, self).get(size)

    def showHist(self, head="dummy", array=None):
        if array is None:
            array = self.get()
        aList = CsurfList(1)
        print(head)
        aList.hist10Show(array)


class CmapsLruHash(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsHash, self).__init__(so, name, dTypes, ffi)


class CmapsPerHash(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsPerHash, self).__init__(so, name, dTypes, ffi)


class CmapsPerArray(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsPerArray, self).__init__(so, name, dTypes, ffi)


class CmapsLruPerHash(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsLruPerHash, self).__init__(so, name, dTypes, ffi)


class CmapsStack(CtableBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsStack, self).__init__(so, name, dTypes, ffi)

    def getArr(self, stack_id):
        return self.getKeyValue(stack_id)


class CmapsEvent(CeventBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CmapsEvent, self).__init__(so, name)
        self._d = dTypes["fvtype"]
        self._ffiType = self._setupFfi(self._d)
        self.cb = None
        self.lostcb = None
        self._ffi = ffi

    @staticmethod
    def _setupFfi(s):
        if s.endswith("]"):
            return s
        else:
            return s + " *"

    def open_perf_buffer(self, cb, lost=None):
        self.cb = cb
        self.lostcb = lost

    def perf_buffer_poll(self, timeout=-1, obj=None):
        if obj is None:
            obj = self
        if not hasattr(obj, "cb"):
            raise ValueError("object %s has no attr callback." % obj)

        if not hasattr(obj, "lostcb"):
            obj.lostcb = None

        def _callback(context, cpu, data, size):
            if obj.cb:
                obj.cb(cpu, data, size)

        def _lostcb(context, cpu, count):
            if obj.lostcb:
                obj.lostcb(cpu, count)
            else:
                print("cpu%d lost %d events" % (cpu, count))

        eventCallback = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_void_p, ct.c_ulong)
        lostCallback = ct.CFUNCTYPE(None, ct.c_void_p, ct.c_int, ct.c_ulonglong)
        _cb = eventCallback(_callback)
        _lost = lostCallback(_lostcb)
        self._so.lbc_set_event_cb(self._id, _cb, _lost)
        self._so.lbc_event_loop(self._id, timeout)

    def event(self, data):
        return self._ffi.cast(self._ffiType, data)


mapsDict = {'event': CmapsEvent,
            'hash': CmapsHash,
            'array': CmapsArray,
            'hist2': CmapsHist2,
            'hist10': CmapsHist10,
            'lruHash': CmapsLruHash,
            'perHash': CmapsPerHash,
            'perArray': CmapsPerArray,
            'lruPerHash': CmapsLruPerHash,
            'stack': CmapsStack, }


def paserMaps(so, name, dTypes):
    t = dTypes['type']
    if t in mapsDict:
        return mapsDict['t'](so, name, dTypes)


if __name__ == "__main__":
    pass
