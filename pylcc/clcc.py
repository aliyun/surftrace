# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     clcc
   Description :
   Author :       liaozhaoyan
   date：          2022/6/12
-------------------------------------------------
   Change Activity:
                   2022/6/12:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from .lbcBase import ClbcLoad
import argparse

examples = """examples:"""


def main():
    parser = argparse.ArgumentParser(
        description="compile libbpf app from remote server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )

    parser.add_argument('-f', '--file', type=str, dest='file', default="", help='set file to compile.')
    parser.add_argument('-a', '--arch', type=str, dest='arch', default="", help='set architecture.')
    parser.add_argument('-v', '--version', type=str, dest='ver', default="", help='set kernel version.')
    parser.add_argument('-i', '--include', type=str, dest='inc', default=None, help='set include path.')

    args = parser.parse_args()
    if args.file == "":
        parser.print_help()
        raise ValueError("need to set **.bpf.c file to compile.")
    ClbcLoad(args.file, arch=args.arch, ver=args.ver, incPath=args.inc)


if __name__ == "__main__":
    main()
    pass
