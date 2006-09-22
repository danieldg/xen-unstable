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
# Copyright (C) 2006 International Business Machines Corp.
# Author: Bryan D. Payne <bdpayne@us.ibm.com>
#============================================================================

"""List the resource label information from the global resource label file
"""
import sys
from xen.util import dictio
from xen.util import security
from xen.xm.opts import OptionError

def help():
    return """Usage: xm resource
    This program lists information for each resource in the
    global resource label file."""

def print_resource_data(access_control):
    """Prints out a resource dictionary to stdout
    """
    for resource in access_control:
        (policy, label) = access_control[resource]
        print resource
        print "    policy: "+policy
        print "    label:  "+label

def main (argv):
    if len(argv) > 1:
        raise OptionError("No arguments required")
    
    try:
        filename = security.res_label_filename
        access_control = dictio.dict_read("resources", filename)
    except:
        print "Resource file not found."
        return

        try:
            file = security.res_label_filename
            access_control = dictio.dict_read("resources", file)
        except:
            security.err("Error reading resource file.")

        print_resource_data(access_control)

if __name__ == '__main__':
    main(sys.argv)


