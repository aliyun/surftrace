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

def callback(line):
    global reqD
    args = transProbeLine(line)
    if args['func'] == 'blk_account_io_start':
        addr = args['args']['request']
        if addr not in reqD:
            res = {"time": float(args["time"]),
                   "pid": args['pid'],
                   "comm": args['args']['comm'],
                   "disk": args['args']['disk']}
            reqD[addr] = res
    else:
        addr = args['args']['request']
        if addr in reqD:
            res = reqD[addr]
            ts = float(args["time"])
            delta = (ts - res["time"]) * 1000.0
            print("%-12d %-7s %-16s %-6d %7.3f" %
                  (int(ts * 1000), res['disk'], res['comm'], res['pid'], delta))
            del reqD[addr]

expr = ['p blk_account_io_start request=%0 disk=%0->rq_disk->disk_name  comm=$comm ',
        'p blk_account_io_done request=%0 disk=%0->rq_disk->disk_name   comm=$comm']

if __name__ == "__main__":
    parser = setupParser("remote")
    surf = surftrace(expr, parser, cb=callback, echo=False)
    surf.start()
    print("%-12s %-7s %-16s %-6s %7s" % ("TIME(ms)", "DISK", "COMM", "PID", "LAT(ms)"))
    surf.loop()
