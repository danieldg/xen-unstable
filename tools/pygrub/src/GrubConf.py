#
# GrubConf.py - Simple grub.conf parsing
#
# Copyright 2005-2006 Red Hat, Inc.
# Jeremy Katz <katzj@redhat.com>
#
# This software may be freely redistributed under the terms of the GNU
# general public license.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import os, sys
import logging

def grub_split(s, maxsplit = -1):
    eq = s.find('=')
    if eq == -1:
        return s.split(None, maxsplit)

    # see which of a space or tab is first
    sp = s.find(' ')
    tab = s.find('\t')
    if (tab != -1 and tab < sp) or (tab != -1 and sp == -1):
        sp = tab

    if eq != -1 and eq < sp or (eq != -1 and sp == -1):
        return s.split('=', maxsplit)
    else:
        return s.split(None, maxsplit)

def grub_exact_split(s, num):
    ret = grub_split(s, num - 1)
    if len(ret) < num:
        return ret + [""] * (num - len(ret))
    return ret

def get_path(s):
    """Returns a tuple of (GrubDiskPart, path) corresponding to string."""
    if not s.startswith('('):
        return (None, s)
    idx = s.find(')')
    if idx == -1:
        raise ValueError, "Unable to find matching ')'"
    d = s[:idx]
    return (GrubDiskPart(d), s[idx + 1:])

class GrubDiskPart(object):
    def __init__(self, str):
        if str.find(',') != -1:
            (self.disk, self.part) = str.split(",", 2)
        else:
            self.disk = str
            self.part = None

    def __repr__(self):
        if self.part is not None:
            return "d%dp%d" %(self.disk, self.part)
        else:
            return "d%d" %(self,disk,)

    def get_disk(self):
        return self._disk
    def set_disk(self, val):
        val = val.replace("(", "").replace(")", "")
        self._disk = int(val[2:])
    disk = property(get_disk, set_disk)

    def get_part(self):
        return self._part
    def set_part(self, val):
        if val is None:
            self._part = val
            return
        val = val.replace("(", "").replace(")", "")
        self._part = int(val)
    part = property(get_part, set_part)

class GrubImage(object):
    def __init__(self, lines):
        self.reset(lines)

    def __repr__(self):
        return ("title: %s\n" 
                "  root: %s\n"
                "  kernel: %s\n"
                "  args: %s\n"
                "  initrd: %s\n" %(self.title, self.root, self.kernel,
                                   self.args, self.initrd))

    def reset(self, lines):
        self._root = self._initrd = self._kernel = self._args = None
        self.title = ""
        self.lines = []
        map(self.set_from_line, lines)

    def set_from_line(self, line, replace = None):
        (com, arg) = grub_exact_split(line, 2)

        if self.commands.has_key(com):
            if self.commands[com] is not None:
                exec("%s = r\"%s\"" %(self.commands[com], arg.strip()))
            else:
                logging.info("Ignored image directive %s" %(com,))
        else:
            logging.warning("Unknown image directive %s" %(com,))

        # now put the line in the list of lines
        if replace is None:
            self.lines.append(line)
        else:
            self.lines.pop(replace)
            self.lines.insert(replace, line)

    def set_root(self, val):
        self._root = GrubDiskPart(val)
    def get_root(self):
        return self._root
    root = property(get_root, set_root)

    def set_kernel(self, val):
        if val.find(" ") == -1:
            self._kernel = get_path(val)
            self._args = None
            return
        (kernel, args) = val.split(None, 1)
        self._kernel = get_path(kernel)
        self._args = args
    def get_kernel(self):
        return self._kernel
    def get_args(self):
        return self._args
    kernel = property(get_kernel, set_kernel)
    args = property(get_args)

    def set_initrd(self, val):
        self._initrd = get_path(val)
    def get_initrd(self):
        return self._initrd
    initrd = property(get_initrd, set_initrd)

    # set up command handlers
    commands = { "title": "self.title",
                 "root": "self.root",
                 "rootnoverify": "self.root",
                 "kernel": "self.kernel",
                 "initrd": "self.initrd",
                 "chainloader": None,
                 "module": None}
        

class GrubConfigFile(object):
    def __init__(self, fn = None):
        self.filename = fn
        self.images = []
        self.timeout = -1
        self._default = 0

        if fn is not None:
            self.parse()

    def parse(self, buf = None):
        if buf is None:
            if self.filename is None:
                raise ValueError, "No config file defined to parse!"

            f = open(self.filename, 'r')
            lines = f.readlines()
            f.close()
        else:
            lines = buf.split("\n")

        img = []
        for l in lines:
            l = l.strip()
            # skip blank lines
            if len(l) == 0:
                continue
            # skip comments
            if l.startswith('#'):
                continue
            # new image
            if l.startswith("title"):
                if len(img) > 0:
                    self.add_image(GrubImage(img))
                img = [l]
                continue
                
            if len(img) > 0:
                img.append(l)
                continue

            (com, arg) = grub_exact_split(l, 2)
            if self.commands.has_key(com):
                if self.commands[com] is not None:
                    exec("%s = r\"%s\"" %(self.commands[com], arg.strip()))
                else:
                    logging.info("Ignored directive %s" %(com,))
            else:
                logging.warning("Unknown directive %s" %(com,))
                
        if len(img) > 0:
            self.add_image(GrubImage(img))

    def set(self, line):
        (com, arg) = grub_exact_split(line, 2)
        if self.commands.has_key(com):
            if self.commands[com] is not None:
                exec("%s = r\"%s\"" %(self.commands[com], arg.strip()))
            else:
                logging.info("Ignored directive %s" %(com,))
        else:
            logging.warning("Unknown directive %s" %(com,))

    def add_image(self, image):
        self.images.append(image)

    def _get_default(self):
        return self._default
    def _set_default(self, val):
        if val == "saved":
            self._default = -1
        else:
            self._default = int(val)

        if self._default < 0:
            raise ValueError, "default must be positive number"
    default = property(_get_default, _set_default)

    def set_splash(self, val):
        self._splash = get_path(val)
    def get_splash(self):
        return self._splash
    splash = property(get_splash, set_splash)

    # set up command handlers
    commands = { "default": "self.default",
                 "timeout": "self.timeout",
                 "fallback": "self.fallback",
                 "hiddenmenu": "self.hiddenmenu",
                 "splashimage": "self.splash",
                 "password": "self.password" }
    for c in ("bootp", "color", "device", "dhcp", "hide", "ifconfig",
              "pager", "partnew", "parttype", "rarp", "serial",
              "setkey", "terminal", "terminfo", "tftpserver", "unhide"):
        commands[c] = None
    del c


if __name__ == "__main__":
    if sys.argv < 2:
        raise RuntimeError, "Need a grub.conf to read"
    g = GrubConfigFile(sys.argv[1])
    for i in g.images:
        print i #, i.title, i.root, i.kernel, i.args, i.initrd
