# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     graphSvg
   Description :
   Author :       liaozhaoyan
   date：          2022/10/4
-------------------------------------------------
   Change Activity:
                   2022/10/4:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from treelib import Tree


class CgraphTree(object):
    def __init__(self):
        super(CgraphTree, self).__init__()

    def _splitLine(self, line):
        rd = {}
        cpu, res = line.split(")", 1)
        rd['cpu'] = int(cpu)

        us, symbol = res.split("|", 1)
        us = us.strip()
        if us.endswith("us"):
            if us[0] in ('+', '!', '#', '*'):
                rd['us'] = float(us[1:-2])
            else:
                rd['us'] = float(us[:-2])
        else:
            rd['us'] = None

        rd['symbol'] = symbol.strip()
        return rd

    def tree(self, lines):
        stack = []
        rtree = Tree()
        last = rtree.root
        for line in lines:
            lined = self._splitLine(line)
            us = lined['us']
            symbol = lined['symbol']
            if us is None:
                if '(' in symbol:
                    func, _ = symbol.split('(', 1)
                    node = rtree.create_node(tag=func, parent=last, data={"func": func})
                    stack.append(node)
                    last = node
            else:
                if symbol.endswith(";"):
                    func, _ = symbol.split('(', 1)
                    rtree.create_node(tag=func, parent=last, data={"func": func, "us": us})
                else:
                    last.data['us'] = us
                    stack.pop()
                    if len(stack) > 0:
                        last = stack[-1]
        root = rtree.root
        if 'us' not in rtree[root].data:
            raise IndexError("bad index.")
        return rtree

    def _filterChildren(self, mtree, nid, tag):
        for child in mtree.children(nid):
            if child.tag == tag:
                return child
        return None

    def mergeTrees(self, trees):
        summary = Tree()
        stack = []
        for tree in trees:
            for nid in tree.expand_tree(mode=Tree.DEPTH, sorting=False):
                node = tree.get_node(nid)
                level = tree.level(nid)
                if level == 0:  # root level
                    if len(stack) == 0:
                        last = summary.root
                        mNode = summary.create_node(tag=node.tag, parent=last, data=node.data)
                        stack.append(mNode)
                    else:
                        mNode = stack[0]
                        mNode.data['us'] += node.data['us']
                        stack = stack[:1]
                else:  # next level
                    last = stack[level - 1]
                    mNode = self._filterChildren(summary, last.identifier, node.tag)
                    if mNode:
                        mNode.data['us'] += node.data['us']
                    else:
                        mNode = summary.create_node(tag=node.tag, parent=last, data=node.data)
                    stack = stack[:level]
                    stack.append(mNode)
        return summary

    def walk(self, tree):
        for nid in tree.expand_tree(mode=Tree.DEPTH, sorting=False):
            node = tree.get_node(nid)
            level = tree.level(nid)
            print(level, node.data)


if __name__ == "__main__":
    pass
