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


try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from surftrace import InvalidArgsException
from surftrace.surfCommon import CsurfList


class CtypeTable(object):
    def __init__(self, fType, ffi):
        super(CtypeTable, self).__init__()
        self._type = fType
        self._ffi = ffi
        self.ffiType = self._setupFfi(self._type)
        self.ffiSize = ffi.sizeof(self._type)

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
        v = self._ffi.new(self._type, k)
        p = self._ffi.cast("void *", v)
        return p

    def load(self, data):
        return self._ffi.cast(self.ffiType, data)


class CeventBase(object):
    def __init__(self, so, name):
        self._so = so
        self._id = self._so.lbc_bpf_get_maps_id(name.encode('utf-8'))
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
        self.keys.clear()
        self.values.clear()

        v = self._ffi.new(self.values.ffiType)
        k1 = self._ffi.new(self.keys.ffiType)
        k2 = self._ffi.new(self.keys.ffiType)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            self._so.lbc_map_lookup_elem(self._id, k2, v)
            self.values.add(v)
            self._ffi.memmove(k1, k2, self.keys.ffiSize)
        return dict(zip(self.keys.output(), self.values.output()))

    def getThenClear(self):
        self.keys.clear()
        self.values.clear()

        v = self._ffi.new(self.values.ffiType)
        k1 = self._ffi.new(self.keys.ffiType)
        k2 = self._ffi.new(self.keys.ffiType)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            r = self._so.lbc_map_lookup_and_delete_elem(self._id, k2, v)
            if r < 0:
                raise InvalidArgsException(
                    "lbc_map_lookup_and_delete_elem return %d, os may not support this opertation." % r)
            self.values.add(v)
            self._ffi.memmove(k1, k2, self.keys.ffiSize)
        r = dict(zip(self.keys.output(), self.values.output()))
        return r

    def getKeys(self):
        self.keys.clear()
        self.values.clear()

        k1 = self._ffi.new(self.keys.ffiType)
        k2 = self._ffi.new(self.keys.ffiType)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self.keys.add(k2)
            self._ffi.memmove(k1, k2, self.keys.ffiSize)
        return self.keys.output()

    def getKeyValue(self, k):
        key = self.keys.input(k)
        v = self._ffi.new(self.values.ffiType)
        if self._so.lbc_map_lookup_elem(self._id, key, v) == 0:
            return self.values.load(v)
        return None

    def clear(self):
        k1 = self._ffi.new(self.keys.ffiType)
        k2 = self._ffi.new(self.keys.ffiType)
        while self._so.lbc_map_get_next_key(self._id, k1, k2) == 0:
            self._so.lbc_map_delete_elem(self._id, k2)
            self._ffi.memmove(k1, k2, self.keys.ffiSize)


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
        self.ffiType = self._setupFfi(self._d)
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

        @self._ffi.callback("void(void *ctx, int cpu, void *data, unsigned int size)")
        def _callback(context, cpu, data, size):
            if obj.cb:
                obj.cb(cpu, data, size)

        @self._ffi.callback("void(void *ctx, int cpu, unsigned long long cnt)")
        def _lostcb(context, cpu, count):
            if obj.lostcb:
                obj.lostcb(cpu, count)
            else:
                print("cpu%d lost %d events" % (cpu, count))

        self._so.lbc_set_event_cb(self._id, _callback, _lostcb)
        self._so.lbc_event_loop(self._id, timeout)

    def event(self, data):
        return self._ffi.cast(self.ffiType, data)


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
