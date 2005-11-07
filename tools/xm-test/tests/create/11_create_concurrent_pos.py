#!/usr/bin/python

# Copyright (C) International Business Machines Corp., 2005
# Authors: Dan Smith <danms@us.ibm.com>

from XmTestLib import *

import time
import random

MIN_DOMS    = 10
MAX_DOMS    = 50
MEM_PER_DOM = 16

domains = []
console = []

free_mem = int(getInfo("free_memory"))

NUM_DOMS = free_mem / MEM_PER_DOM

if NUM_DOMS < MIN_DOMS:
    SKIP("Need %i MB of RAM to start %i@%iMB domains! (%i MB avail)" %
         (MIN_DOMS * MEM_PER_DOM, MIN_DOMS, MEM_PER_DOM,
          free_mem))

if NUM_DOMS > MAX_DOMS:
    if verbose:
        print "*** %i doms is too many: capping at %i" % (NUM_DOMS, MAX_DOMS)
    NUM_DOMS = MAX_DOMS

if verbose:
    print "Watch out!  I'm trying to create %i DomUs!" % NUM_DOMS

for d in range(0, NUM_DOMS):
    dom = XmTestDomain(name="11_create_%i" % d,
                       extraOpts={"memory":str(MEM_PER_DOM)})

    try:
        dom.start()
    except DomainError, e:
        if verbose:
            print str(e)
        FAIL("[%i] Failed to create domain" % d)

    try:
        cons = XmConsole(dom.getName())
        cons.sendInput("foo")
        cons.runCmd("ls")
    except ConsoleError, e:
        FAIL("[%i] Failed to attach console to %s" % (d, dom.getName()))

    domains.append(dom)
    console.append(cons)
    
    if verbose:
        print "[%i] Started %s" % (d, dom.getName())


# If we make it here, we will test several of the DomUs consoles

for i in range(0,5):
    c = random.randint(0, NUM_DOMS-1)

    if verbose:
        print "Testing console of %s" % domains[c].getName()

    try:
        run = console[c].runCmd("ls")
    except ConsoleError, e:
        FAIL(str(e))

    if run["return"] != 0:
        FAIL("'ls' returned invalid %i != 0" % run["return"])
