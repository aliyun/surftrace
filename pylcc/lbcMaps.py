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

import sys
try:
    from collections.abc import MutableMapping
except ImportError:
    from collections import MutableMapping
from surftrace import InvalidArgsException
from surftrace.surfCommon import CsurfList


class CffiValue(object):
    """
    This is the object container provided for types like structs.
    If the numeric type in the data stream is not within python's numeric range,
    such as struct union etc, then need a container to load all values.
    """
    def __init__(self):
        super(CffiValue, self).__init__()

    def __repr__(self):
        """
        object native method, show ffi value information.
        Returns:
         ffi value information
        Raises:
         None
        """
        res = {}
        for mem in dir(self):
            if mem.startswith("__") and mem.endswith("__"):
                # strip object native member
                continue
            res[mem] = getattr(self, mem)
        return str(res)


class CffiTrans(object):
    """
    This is the conversion class of the FFI interface,
    you only need to instantiate the class and call the value member function,
    then you will get the native python value from c stream.
    """
    if sys.version_info.major == 2:
        # long is a data type that can be displayed directly for python2
        _directList = (int, str, float, long)
    else:
        _directList = (int, str, float)
    _cNativeType = ("char", "short", "int", "long", "float", "double", "enum")

    def __init__(self, ffi):
        """
        object native method, show ffi value information.
        Parameters:
         param1 - cffi object to analytical data
        Returns:
         CffiTrans
        """
        super(CffiTrans, self).__init__()
        self._ffi = ffi

    def value(self, e):
        """
        transform ffi cast stream to python value.
        Parameters:
         param1 - ffi cast stream
        Returns:
         python value, may int/string/CffiValue
        """
        mems = dir(e)
        if len(mems) > 0:   # check cast stream contains child nodes
            v = self._values(e, mems)
        else:
            v = self._value(e)
        return v

    def _value(self, e):
        """
        transform ffi cast stream to python value, single mode.
        Parameters:
         param1 - ffi cast stream
        Returns:
         python value, just a single value.
        Raise:
         ValueError not support type.
        """
        sType = self._ffi.getctype(self._ffi.typeof(e))
        cEnd = sType[-1]
        if cEnd == "*":     # for point and native value
            if sType.endswith("* *"):   # point
                v = self._point(sType[:-2])
            else:
                v = self._ffi.unpack(e, 1)[0]
        elif cEnd == "]":
            v = self._array(e, sType)
        else:
            raise ValueError("not support type: %s" % sType)
        return v

    def _values(self, e, mems):
        """
        transform ffi cast stream to python value, multi mode.
        Parameters:
         param1 - ffi cast stream
         param2 - ffi cast stream members
        Returns:
         CffiValue object.
        Raise:
         ValueError not support type.
        """
        v = CffiValue()
        for mem in mems:
            vMem = getattr(e, mem)
            if type(getattr(e, mem)) in CffiTrans._directList:   # direct type
                setattr(v, mem, vMem)
            else:
                tMem = self._ffi.getctype(self._ffi.typeof(vMem))
                cEnd = tMem[-1]     # tMem may like struct child *[2], so check by reverse order
                if cEnd == ']':     # array type at first
                    setattr(v, mem, self._array(vMem, tMem))
                elif "*" in tMem:   # then point type
                    setattr(v, mem, self._point(tMem))
                elif dir(vMem) > 0:     # for struct etc，recursive call value
                    setattr(v, mem, self.value(vMem))
                else:
                    raise ValueError("not support type: %s" % tMem, vMem)
        return v

    def _array(self, e, tMem):
        """
        transform ffi array to python value, parse array size at first.
        Parameters:
         param1 - ffi cast stream
         param2 - ffi member from stream
        Returns:
         python list
        """
        tType, sArr = tMem.split("[", 1)
        return self._unpackArry(tType, e, sArr)

    def _unpackArry(self, tType, e, sArr):
        """
        unpack ffi array to python value, parse array size at first.
        Parameters:
         param1 - ffi member type from stream
         param2 - ffi cast stream
         param3 - size of Array, string type.
        Returns:
         python list
        Raise:
         ValueError not support type.
        """
        res = None
        sNum, remain = sArr.split(']', 1)
        num = int(sNum)
        if num > 0:     # may zero array
            res = []
            t = tType.split(" ")[-1]
            if len(remain):  # multi array, recursive call
                for i in range(num):
                    res.append(self._unpackArry(tType, e[i], remain[1:]))
            elif t in CffiTrans._cNativeType:
                if tType == "char":     # for string
                    res = self._ffi.string(e)
                else:
                    for i in range(num):  # for normal value
                        res.append(e[i])
            elif "*" in tType:  # point
                for i in range(num):
                    res.append(self._point(tType))
            elif dir(e) > 0:   # struct? array type
                for i in range(num):
                    res.append(self.value(e[i]))
            else:
                raise ValueError("not support type: %s" % tType, e)
        return res

    @staticmethod
    def _point(sType):
        """
        show point information.
        Parameters:
         param1 - ffi cast stream
         param2 - ffi member from stream
        Returns:
         python string to show point info.
        """
        res = "point:%s" % sType
        return res


class CtypeTable(object):
    def __init__(self, fType, ffi):
        super(CtypeTable, self).__init__()
        self._type = fType
        self.ffiType = self._setupFfi(self._type)
        self.ffiSize = ffi.sizeof(self._type)
        self._obj = CffiTrans(ffi)

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

    def load(self, data):
        return self._obj.value(data)


class CeventBase(object):
    def __init__(self, so, name, ffi):
        self._so = so
        self._id = self._so.lbc_bpf_get_maps_id(name.encode('utf-8'))
        if self._id < 0:
            raise InvalidArgsException("map %s, not such event" % name)
        self.name = name
        super(CeventBase, self).__init__()
        self._ffi = ffi

    @staticmethod
    def _setupFfi(s):
        if s.endswith("]"):
            return s
        else:
            return s + " *"


class CtableBase(CeventBase):
    def __init__(self, so, name, dTypes, ffi):
        super(CtableBase, self).__init__(so, name, ffi)
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
        res = None
        key = self._ffi.new(self.keys.ffiType, k)
        value = self._ffi.new(self.values.ffiType)
        if self._so.lbc_map_lookup_elem(self._id, key, value) == 0:
            res = self.values.load(value)
        return res

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
        super(CmapsLruHash, self).__init__(so, name, dTypes, ffi)


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
        super(CmapsEvent, self).__init__(so, name, ffi)
        self._d = dTypes["fvtype"]
        self.ffiType = self._setupFfi(self._d)
        self.cb = None
        self.lostcb = None
        self._obj = CffiTrans(ffi)

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
        e = self._ffi.cast(self.ffiType, data)
        return self._obj.value(e)


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
