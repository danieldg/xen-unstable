#============================================================================
# This library is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General Public
# License as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#============================================================================
# Copyright (C) 2004, 2005 Mike Wray <mike.wray@hp.com>
#============================================================================

"""Get dmesg output for this node.
"""

import os
import xen.lowlevel.xc

class XendDmesg:
    def __init__(self):
        self.xc = xen.lowlevel.xc.new()

    def info(self):
        return self.xc.readconsolering()

    def clear(self):
        self.xc.readconsolering(True)

def instance():
    global inst
    try:
        inst
    except:
        inst = XendDmesg()
    return inst

