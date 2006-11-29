#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>
#
# A couple of simple tests that test ACM security extensions
# for the xm tool. The following xm subcommands are tested:
#
# - makepolicy
# - labels
# - rmlabel
# - addlabel
# - getlabel
# - resources

from XmTestLib import *
from xen.util import security
import commands
import os
import re

testpolicy = "xm-test"
testlabel = "blue"
vmconfigfile = "/tmp/xm-test.conf"
testresource = "phy:ram0"

if not isACMEnabled():
    SKIP("Not running this test since ACM not enabled.")

status, output = traceCommand("xm makepolicy %s" % (testpolicy))
if status != 0 or output != "":
    FAIL("'xm makepolicy' failed with status %d and output\n%s" %
         (status,output));

status, output = traceCommand("xm labels %s" % (testpolicy))
if status != 0:
    FAIL("'xm labels' failed with status %d.\n" % status)

#Need to get a vm config file - just have it written to a file
domain = XmTestDomain()
domain.config.write(vmconfigfile)

#Whatever label it might have - remove it
status, output = traceCommand("xm rmlabel dom %s" %
                              (vmconfigfile))

status, output = traceCommand("xm addlabel %s dom %s %s" %
                              (testlabel, vmconfigfile, testpolicy))
if status != 0:
    FAIL("'xm addlabel' failed with status %d.\n" % status)

status, output = traceCommand("xm getlabel dom %s" %
                              (vmconfigfile))

if status != 0:
    FAIL("'xm getlabel' failed with status %d, output:\n%s" %
         (status, output))
if output != "policy=%s,label=%s" % (testpolicy,testlabel):
    FAIL("Received unexpected output from 'xm getlabel': \n%s" %
         (output))


status, output = traceCommand("xm rmlabel dom %s" %
                              (vmconfigfile))

if status != 0:
    FAIL("'xm rmlabel' failed with status %d, output: \n%s" %
         (status,output))
if output != "":
    FAIL("Received unexpected output from 'xm rmlabel': \n%s" %
         (output))

status, output = traceCommand("xm getlabel dom %s" %
                              (vmconfigfile))

if output != "Error: 'Domain not labeled'":
    FAIL("Received unexpected output from 'xm getlabel': \n%s" %
         (output))

#Whatever label the resource might have, remove it
status, output = traceCommand("xm rmlabel res %s" %
                              (testresource))

status, output = traceCommand("xm addlabel %s res %s %s" %
                              (testlabel, testresource, testpolicy))
if status != 0:
    FAIL("'xm addlabel' on resource failed with status %d.\n" % status)

status, output = traceCommand("xm getlabel res %s" % (testresource))

if status != 0:
    FAIL("'xm getlabel' on resource failed with status %d, output:\n%s" %
         (status, output))
if output != "policy=%s,label=%s" % (testpolicy,testlabel):
    FAIL("Received unexpected output from 'xm getlabel': \n%s" %
         (output))

status, output = traceCommand("xm resources")

if status != 0:
    FAIL("'xm resources' did not run properly")
if not re.search(security.unify_resname(testresource), output):
    FAIL("'xm resources' did not show the tested resource '%s'." %
         testresource)

status, output = traceCommand("xm rmlabel res %s" %
                              (testresource))

if status != 0:
    FAIL("'xm rmlabel' on resource failed with status %d, output: \n%s" %
         (status,output))
if output != "":
    FAIL("Received unexpected output from 'xm rmlabel': \n%s" %
         (output))

status, output = traceCommand("xm getlabel res %s" %
                              (testresource))

if output != "Error: 'Resource not labeled'":
    FAIL("Received unexpected output from 'xm getlabel': \n%s" %
         (output))
