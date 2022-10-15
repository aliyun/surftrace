# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     surfGraph
   Description :
   Author :       liaozhaoyan
   date：          2022/10/4
-------------------------------------------------
   Change Activity:
                   2022/10/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import sys
import argparse
import time
import re
import pickle
from collections import deque
from treelib import Tree
from .ftrace import ftrace
from .graphTree import CgraphTree
from quickSvg import Flame


def getValue(data):
    return data['us']


def getNote(tree, node):
    root = tree.get_node(tree.root)
    perRoot = node.data['us'] / root.data['us'] * 100.0

    parent = tree.parent(node.identifier)
    if parent is None:
        perParent = 100.0
    else:
        perParent = node.data['us'] / parent.data['us'] * 100.0
    return "cost %f us, %f%% from root, %f%% from parent" % (node.data['us'], perRoot, perParent)


class surfGraph(ftrace):
    def __init__(self, symbol, mode="raw", output=True, step=True):
        super(surfGraph, self).__init__(show=False, echo=True, instance=None)
        self._symbol = symbol
        self._record = 'nop'

        cbD = {
            "raw": self._cbLine,
            'tree': self._cbTree,
            "walk": self._cbWalk,
            "svg": self._cbSvg,
        }
        if mode not in cbD.keys():
            raise ValueError("mode only support %s" % str(cbD.keys()))
        self._cb = cbD[mode]
        self._funStart = False
        self._reStart = re.compile(r"^[\d]+\) +\|  [\w]+\(\) \{")
        self._reEnd = re.compile(r"^[\d]\).+\|  \}")
        self._reLine = re.compile(r"^[\d]\).+\|")

        self._serial = 1
        self._lines = []
        self._output = output
        self._step = step
        self._tree = None
        self._trees = deque(maxlen=32)

    def _setupTracer(self, symbol):
        Path = self.baseDir + "/tracing/current_tracer"
        self._record = self._c.cmd("cat %s" % Path)
        self._echoPath(Path, "nop")

        time.sleep(0.5)
        fPath = self.baseDir + "/tracing/set_graph_function"
        self._echoPath(fPath, symbol)
        self._echoPath(Path, "function_graph")

    def _saveTree(self, tree):
        self._trees.append(tree)
        if self._tree is None:
            self._tree = tree
        else:
            t = CgraphTree()
            self._tree = t.mergeTrees([self._tree, tree])

    def _setupTree(self, line, cbTree):
        if self._funStart:
            if self._reLine.search(line):
                self._lines.append(line)
                if self._reEnd.search(line):
                    self._funStart = False
                    t = CgraphTree()
                    try:
                        tree = t.tree(self._lines)
                    except IndexError:
                        return

                    node = tree.get_node(tree.root)
                    if 'us' not in node.data:
                        return

                    if self._output:
                        self._saveTree(tree)
                    cbTree(tree)
        elif self._reStart.search(line):
            res = line.split("|")[1].strip()
            res = res.split("(")[0]
            if res == self._symbol:
                self._funStart = True
                self._lines = [line]

    def _cbLine(self, line):
        print("%s" % line)

    def _treeShow(self, tree):
        print(tree)

    def _walkShow(self, tree):
        for nid in tree.expand_tree(mode=Tree.DEPTH, sorting=True):
            node = tree.get_node(nid)
            level = tree.level(nid)
            print(level, node.data)

    def _svgShow(self, tree):
        if self._step:
            print("save %s-%d.svg" % (self._symbol, self._serial))
            svg = Flame("%s-%d.svg" % (self._symbol, self._serial))
            svg.render(tree, getValue, getNote, "%s" % self._symbol)
        else:
            print("jump %s-%d.svg" % (self._symbol, self._serial))
        self._serial += 1

    def _cbTree(self, line):
        self._setupTree(line, self._treeShow)

    def _cbWalk(self, line):
        self._setupTree(line, self._walkShow)

    def _cbSvg(self, line):
        self._setupTree(line, self._svgShow)

    def procLine(self, line):
        # print(line)
        self._cb(line)

    def start(self):
        func = self._checkAvailable(self._symbol)
        if func is None:
            raise ValueError("symbol %s is not an available function." % self._symbol)

        self._setupTracer(func)
        super(surfGraph, self).start()

    def stop(self):
        super(surfGraph, self).stop()
        Path = self.baseDir + "/tracing/set_graph_function"
        self._echoPath(Path, '')

        if self._tree:
            if self._output:
                dOut = {"merge": self._tree,
                        "trees": self._trees,
                        }
                s = pickle.dumps(dOut, protocol=2)
                with open("%s.tree" % self._symbol, 'wb') as f:
                    f.write(s)

            if self._cb == self._cbSvg:
                svg = Flame("%s.svg" % self._symbol)
                svg.render(self._tree, getValue, getNote, "%s" % self._symbol)
                print("write %s.svg" % self._symbol)


def main():
    examples = """examples: surfGraph -f __do_fault"""

    parser = argparse.ArgumentParser(
        description="kernel function call graph tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=examples
    )

    parser.add_argument('-f', '--function', type=str, dest='function', default="", help='set function to call graph.')
    parser.add_argument('-m', '--mode', type=str, dest='mode', default="svg",
                        help="set output mode, support svg(default)/tree/walk/raw")
    parser.add_argument('-s', '--step', type=int, dest='step', default=True,
                        help="write file by every step, only for svg mode.")
    parser.add_argument('-o', '--output', type=int, dest='output', default=True,
                        help="save trees to *.tree file, 32 max")

    args = parser.parse_args()
    symbol = args.function
    graph = surfGraph(symbol, mode=args.mode, output=args.output, step=args.step)
    graph.start()
    graph.loop()


if __name__ == "__main__":
    pass
