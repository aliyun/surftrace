# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     biosnoop
   Description :
   Author :       zhongwuqiang
   date：          2022/2/18
-------------------------------------------------
   Change Activity:
                   2022/2/18:
-------------------------------------------------
"""
__author__ = 'zhongwuqiang'

from surftrace import surftrace, setupParser
from surftrace.surfCommon import CsurfList,transProbeLine

reqD = {}

l = CsurfList(2048)
def callback(line):
    global reqD,l
    args = transProbeLine(line)
    if args['func'] == 'blk_account_io_start':
        addr = args['args']['request']
        if addr not in reqD:
            reqD[addr] = float(args["time"])
    else:
        addr = args['args']['request']
        if addr in reqD:
            res = reqD[addr]
            ts = float(args["time"])
            delat = (ts - res) * 1000.0
            l.append(int(delat*1000))
            del reqD[addr]

expr = ['p blk_account_io_start request=%0',
        'p blk_account_io_done request=%0']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print('Tracing block device I/O... Hit Ctrl-C to end.')
    surf.loop()
    print("\n\n@usecs:")
    l.hist2()


