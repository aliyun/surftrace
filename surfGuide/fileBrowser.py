# -*- coding: utf-8 -*-
# cython:language_level=3
"""
-------------------------------------------------
   File Name：     fileBrowser
   Description :
   Author :       liaozhaoyan
   date：          2021/12/23
-------------------------------------------------
   Change Activity:
                   2021/12/23:
-------------------------------------------------
"""
__author__ = 'liaozhaoyan'

import itertools
import re
import os
import urwid
from .fileChecker import surfCheck

from .conBase import CconBase, log
from .createSurf import CcreateSurf
from .editExpression import CeditExpression
from .lbcClient import ClbcClient

# global cache of widgets
_widget_cache = {}

def add_widget(path, widget):
    """Add the widget for a given path"""
    _widget_cache[path] = widget

def get_flagged_names():
    """Return a list of all filenames marked as flagged."""
    l = []
    for w in _widget_cache.values():
        if w.flagged:
            l.append(w.get_node().get_value())
    return l

def clear_flagged_names():
    for w in _widget_cache.values():
        w.flagged = False

# store path components of initial current working directory
_initial_cwd = []

def store_initial_cwd(name):
    """Store the initial current working directory path components."""

    global _initial_cwd
    _initial_cwd = name.split(dir_sep())

def starts_expanded(name):
    """Return True if directory is a parent of initial cwd."""

    if name == '/':
        return True

    l = name.split(dir_sep())
    if len(l) > len(_initial_cwd):
        return False

    if l != _initial_cwd[:len(l)]:
        return False

    return True


def escape_filename_sh(name):
    """Return a hopefully safe shell-escaped version of a filename."""

    # check whether we have unprintable characters
    for ch in name:
        if ord(ch) < 32:
            # found one so use the ansi-c escaping
            return escape_filename_sh_ansic(name)

    # all printable characters, so return a double-quoted version
    name.replace('\\','\\\\')
    name.replace('"','\\"')
    name.replace('`','\\`')
    name.replace('$','\\$')
    return name


def escape_filename_sh_ansic(name):
    """Return an ansi-c shell-escaped version of a filename."""
    out =[]
    # gather the escaped characters into a list
    for ch in name:
        if ord(ch) < 32:
            out.append("\\x%02x"% ord(ch))
        elif ch == '\\':
            out.append('\\\\')
        else:
            out.append(ch)

    # slap them back together in an ansi-c quote  $'...'
    return "$'" + "".join(out) + "'"

SPLIT_RE = re.compile(r'[a-zA-Z]+|\d+')
def alphabetize(s):
    L = []
    for isdigit, group in itertools.groupby(SPLIT_RE.findall(s), key=lambda x: x.isdigit()):
        if isdigit:
            for n in group:
                L.append(('', int(n)))
        else:
            L.append((''.join(group).lower(), 0))
    return L

def dir_sep():
    """Return the separator used in this os."""
    return getattr(os.path,'sep','/')


class FlagFileWidget(urwid.TreeWidget):
    # apply an attribute to the expand/unexpand icons
    unexpanded_icon = urwid.AttrMap(urwid.TreeWidget.unexpanded_icon,
        'dirmark')
    expanded_icon = urwid.AttrMap(urwid.TreeWidget.expanded_icon,
        'dirmark')

    def __init__(self, frame, node, isFile=False):
        self._frame = frame
        self.__super.__init__(node)
        # insert an extra AttrWrap for our own use
        self._w = urwid.AttrWrap(self._w, None)
        self._isFile = isFile
        self.flagged = False
        self.update_w()

    def selectable(self):
        return True

    def keypress(self, size, key):
        """allow subclasses to intercept keystrokes"""
        key = self.__super.keypress(size, key)
        if key:
            key = self.unhandled_keys(size, key)
        return key

    def unhandled_keys(self, size, key):
        """
        Override this method to intercept keystrokes in subclasses.
        Default behavior: Toggle flagged on space, ignore other keys.
        """
        if key == " ":
            if self._isFile:
                self.flagged = True
                names = [escape_filename_sh(x) for x in get_flagged_names()]
                res = surfCheck(names[0])
                if res == "ok.":
                    # self._frame._footer.set_text("select %d" % res)
                    edit = CeditExpression(names[0])
                    self._frame.switch_widget(edit)
                else:
                    self._frame._footer.set_text("%s" % res)
                    clear_flagged_names()
            else:
                self._frame._footer.set_text("should select a file, not dir")
                # self.update_w()
        elif key == 'c' or key == 'C':
            self.flagged = True
            name = [escape_filename_sh(x) for x in get_flagged_names()][0]
            if not os.path.isdir(name):
                name, _ = os.path.split(name)
            create = CcreateSurf(name)
            self._frame.switch_widget(create)
        else:
            return key

    def update_w(self):
        """Update the attributes of self.widget based on self.flagged.
        """
        if self.flagged:
            self._w.attr = 'flagged'
            self._w.focus_attr = 'flagged focus'
        else:
            self._w.attr = 'body'
            self._w.focus_attr = 'focus'

class FileTreeWidget(FlagFileWidget):
    """Widget for individual files."""
    def __init__(self, frame, node):
        self.__super.__init__(frame, node, True)
        path = node.get_value()
        add_widget(path, self)

    def get_display_text(self):
        return self.get_node().get_key()

class EmptyWidget(urwid.TreeWidget):
    """A marker for expanded directories with no contents."""
    def get_display_text(self):
        return ('flag', '(empty directory)')

class ErrorWidget(urwid.TreeWidget):
    """A marker for errors reading directories."""

    def get_display_text(self):
        return ('error', "(error/permission denied)")


class DirectoryWidget(FlagFileWidget):
    """Widget for a directory."""
    def __init__(self, frame, node):
        self.__super.__init__(frame, node)
        path = node.get_value()
        add_widget(path, self)
        self.expanded = starts_expanded(path)
        self.update_expanded_icon()

    def get_display_text(self):
        node = self.get_node()
        if node.get_depth() == 0:
            return "/"
        else:
            return node.get_key()


class FileNode(urwid.TreeNode):
    """Metadata storage for individual files"""

    def __init__(self, path, frame, parent=None):
        self._frame = frame
        depth = path.count(dir_sep())
        key = os.path.basename(path)
        urwid.TreeNode.__init__(self, path, key=key, parent=parent, depth=depth)

    def load_parent(self):
        parentname, myname = os.path.split(self.get_value())
        parent = DirectoryNode(parentname, self._frame)
        parent.set_child_node(self.get_key(), self)
        return parent

    def load_widget(self):
        return FileTreeWidget(self._frame, self)

class EmptyNode(urwid.TreeNode):
    def load_widget(self):
        return EmptyWidget(self)


class ErrorNode(urwid.TreeNode):
    def load_widget(self):
        return ErrorWidget(self)


class DirectoryNode(urwid.ParentNode):
    """Metadata storage for directories"""

    def __init__(self, path, frame, parent=None):
        self._frame = frame
        if path == dir_sep():
            depth = 0
            key = None
        else:
            depth = path.count(dir_sep())
            key = os.path.basename(path)
        urwid.ParentNode.__init__(self, path, key=key, parent=parent,
                                  depth=depth)

    def load_parent(self):
        parentname, myname = os.path.split(self.get_value())
        parent = DirectoryNode(parentname, self._frame)
        parent.set_child_node(self.get_key(), self)
        return parent

    def load_child_keys(self):
        dirs = []
        files = []
        try:
            path = self.get_value()
            # separate dirs and files
            for a in os.listdir(path):
                if os.path.isdir(os.path.join(path,a)):
                    dirs.append(a)
                else:
                    files.append(a)
        except OSError as e:
            depth = self.get_depth() + 1
            self._children[None] = ErrorNode(self, parent=self, key=None,
                                             depth=depth)
            return [None]

        # sort dirs and files
        dirs.sort(key=alphabetize)
        files.sort(key=alphabetize)
        # store where the first file starts
        self.dir_count = len(dirs)
        # collect dirs and files together again
        keys = dirs + files
        if len(keys) == 0:
            depth=self.get_depth() + 1
            self._children[None] = EmptyNode(self, parent=self, key=None,
                                             depth=depth)
            keys = [None]
        return keys

    def load_child_node(self, key):
        """Return either a FileNode or DirectoryNode"""
        index = self.get_child_index(key)
        if key is None:
            return EmptyNode(None)
        else:
            path = os.path.join(self.get_value(), key)
            if index < self.dir_count:
                return DirectoryNode(path, self._frame, parent=self)
            else:
                path = os.path.join(self.get_value(), key)
                return FileNode(path, self._frame, parent=self)

    def load_widget(self):
        return DirectoryWidget(self._frame, self)

class CfileBrowser(CconBase):
    def __init__(self):
        super(CfileBrowser, self).__init__()

    def setupView(self):
        cwd = os.getcwd()
        store_initial_cwd(cwd)
        self._setupHeadFoot("select a file. SPACE to select, C/c to create", "key:UP DOWN.PAGEUP PAGEDOWN.+-.LEFT HOME END")
        treeList = DirectoryNode(cwd, self)
        return self._setupTree(treeList)

    def key_proc(self, key):
        if key == ";":
            names = [escape_filename_sh(x) for x in get_flagged_names()]
            self._footer.set_text("select %s" % names)

if __name__ == "__main__":
    b = CfileBrowser()
    b.setupDb(ClbcClient())
    b.loop()
    pass
