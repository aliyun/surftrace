# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     regSplit
   Description :
   Author :       liaozhaoyan
   date：          2022/3/19
-------------------------------------------------
   Change Activity:
                   2022/3/19:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

from .surfException import ExprException

# copy from surf expression.py
probeReserveVars = ('common_pid', 'common_preempt_count', 'common_flags', 'common_type')
archRegd = {'x86_64': ('di', 'si', 'dx', 'cx', 'r8', 'r9', 'ax', 'bx',
                       'sp', 'bp', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',),
            'x86': ('di', 'si', 'dx', 'cx'),
            'aarch64': ('x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8', 'x9',
                        'x10', 'x11', 'x12', 'x13', 'x14', 'x15', 'x16', 'x17', 'x18', 'x19',
                        'x20', 'x21', 'x22', 'x23', 'x24', 'x25', 'x26', 'x27', 'x28', 'x29',
                        'x30', 'x31'),}


def maxNameString(cells, t):
    rs = cells[0][t]
    ret = ""
    for i, r in enumerate(rs):
        for f in cells[1:]:
            sFunc = f[t]
            if len(sFunc) < i or sFunc[i] != r:
                return ret
        ret += r
    return ret


def isStruct(text):
    strips = ("const ", "volatile ")
    for s in strips:
        text = text.replace(s, "")
    text = text.strip()
    if text.startswith("struct ") or text.startswith("union "):
        return text
    return None


def splitExpr(text):
    es = []
    e = ""
    count = 0
    for c in text:
        if c == '(':
            count += 1
        elif c == ")":
            count -= 1
            if count < 0:
                return None
        elif count == 0 and c == " ":
            if e != "":
                es.append(e)
            e = ""
            continue
        e += c
    if e != "":
        es.append(e)
    return es


def spiltInputLine(line):
    res = {}
    es = splitExpr(line)
    esLen = len(es)
    if esLen < 2:
        raise ExprException("%s is a single expression" % line)
    if es[0] not in ('p', 'r', 'e', 'P', 'R'):
        raise ExprException("not support %s event." % es[0])
    res['type'] = es[0]
    res['symbol'] = es[1]
    if esLen >= 3:
        if es[-1].startswith("f:"):
            res['filter'] = es[-1][2:]
            res['args'] = " ".join(es[2:-1])
        else:
            res['filter'] = ""
            res['args'] = " ".join(es[2:])
    else:
        res['filter'] = ""; res['args'] = ""
    return res


def unpackRes(res):
    s = "%s %s" % (res['type'], res['symbol'])
    if res['filter'] == "":
        if res['args'] == "":
            return s
        else:
            return s + " %s" % res['args']
    else:
        if res['args'] == "":
            return s + " f:%s" % res['filter']
        else:
            return s + " %s f:%s" % (res['args'], res['filter'])


def stripPoint(sStruct):
    return sStruct.strip("*").strip()


def regIndex(reg, arch='x86'):
    regs = archRegd[arch]
    try:
        return regs.index(reg)
    except ValueError:
        raise ExprException('%s is not a %s register.' % (reg, arch))


def transReg(i, arch='x86'):
    try:
        return archRegd[arch][i]
    except IndexError:
        raise ExprException('reg index %d overflow.' % i)


if __name__ == "__main__":
    pass
