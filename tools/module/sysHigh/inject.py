# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     inject.py
   Description :
   Author :       liaozhaoyan
   date：          2022/10/20
-------------------------------------------------
   Change Activity:
                   2022/10/20:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import time
import argparse


class Cinject(object):
    def __init__(self, interval, loop, total):
        super(Cinject, self).__init__()
        self._interval = interval
        self._loop = loop
        self._total = total

    def _inject(self):
        with open("/proc/coolbpf/sys_high", "w") as f:
            f.write("%d" % self._loop)

    def work(self):
        start = time.time()
        for i in range(self._total):
            self._inject()
            time.sleep(self._interval)
        end = time.time()
        print("test use %f seconds." % (end - start))


if __name__ == "__main__":
    examples = """examples: python inject -i 0.5 -l 1000000 -t 100"""

    parser = argparse.ArgumentParser(
        description="inject sys high.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )
    parser.add_argument('-i', '--interval', type=float, dest='interval', default=0.1,
                        help='set injecting interval time, uint second.')
    parser.add_argument('-l', '--loop', type=int, dest='loop', default=10000,
                        help='set kernel loops.')
    parser.add_argument('-t', '--total', type=int, dest='total', default=100,
                        help='set total inject times.')
    args = parser.parse_args()
    inj = Cinject(args.interval, args.loop, args.total)
    inj.work()
    pass
