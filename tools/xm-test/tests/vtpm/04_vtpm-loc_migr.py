#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2006
# Author: Stefan Berger <stefanb@us.ibm.com>

# Positive Test: create domain with virtual TPM attached at build time,
#                check list of pcrs; locally migrate the domain and
#                check list of pcrs again
#                This test does local live migration.

from XmTestLib import *
from vtpm_utils import *
import commands
import os
import os.path

config = {"vtpm":"instance=1,backend=0"}
domain = XmTestDomain(extraConfig=config)
consoleHistory = ""

try:
    console = domain.start()
except DomainError, e:
    if verbose:
        print e.extra
    vtpm_cleanup(domain.getName())
    FAIL("Unable to create domain")

domName = domain.getName()

try:
    console.sendInput("input")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL(str(e))

try:
    run = console.runCmd("cat /sys/devices/platform/tpm_vtpm/pcrs")
except ConsoleError, e:
    saveLog(console.getHistory())
    vtpm_cleanup(domName)
    FAIL(str(e))

if re.search("No such file",run["output"]):
    vtpm_cleanup(domName)
    FAIL("TPM frontend support not compiled into (domU?) kernel")

consoleHistory = console.getHistory()
domain.closeConsole()

old_domid = domid(domName)

loop = 0
while loop < 3:
    try:
        status, ouptut = traceCommand("xm migrate -l %s localhost" %
                                      domName,
                                      timeout=90)
    except TimeoutError, e:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL(str(e))

    if status != 0:
        saveLog(consoleHistory)
        vtpm_cleanup(domName)
        FAIL("xm migrate did not succeed. External device migration activated?")


    domName = domain.getName()
    new_domid = domid(domName)

    if (old_domid == new_domid):
        vtpm_cleanup(domName)
        FAIL("xm migrate failed, domain id is still %s (loop=%d)" %
             (old_domid,loop))

    try:
        console = domain.getConsole()
    except ConsoleError, e:
        vtpm_cleanup(domName)
        FAIL(str(e))

    try:
        run = console.runCmd("cat /sys/devices/platform/tpm_vtpm/pcrs")
    except ConsoleError, e:
        saveLog(console.getHistory())
        vtpm_cleanup(domName)
        FAIL(str(e))
    loop += 1

domain.closeConsole()

domain.stop()

vtpm_cleanup(domName)

if not re.search("PCR-00:",run["output"]):
	FAIL("Virtual TPM is not working correctly on /dev/vtpm on backend side")
