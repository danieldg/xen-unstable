# Copyright (C) 2005 Christian Limpach <Christian.Limpach@cl.cam.ac.uk>
# Copyright (C) 2005 XenSource Ltd

# This file is subject to the terms and conditions of the GNU General
# Public License.  See the file "COPYING" in the main directory of
# this archive for more details.

import os
import re
import select
import string
import sxp
from struct import pack, unpack, calcsize

from xen.util.xpopen import xPopen3

import xen.lowlevel.xc

from xen.xend.xenstore.xsutil import IntroduceDomain

from XendError import XendError
from XendLogging import log

SIGNATURE = "LinuxGuestRecord"
PATH_XC_SAVE = "/usr/libexec/xen/xc_save"
PATH_XC_RESTORE = "/usr/libexec/xen/xc_restore"

sizeof_int = calcsize("i")
sizeof_unsigned_long = calcsize("L")


xc = xen.lowlevel.xc.new()


def write_exact(fd, buf, errmsg):
    if os.write(fd, buf) != len(buf):
        raise XendError(errmsg)

def read_exact(fd, size, errmsg):
    buf = os.read(fd, size)
    if len(buf) != size:
        raise XendError(errmsg)
    return buf

def save(fd, dominfo, live):
    write_exact(fd, SIGNATURE, "could not write guest state file: signature")

    config = sxp.to_string(dominfo.sxpr())

    domain_name = dominfo.getName()

    if live:
        dominfo.setName('migrating-' + domain_name)

    try:
        write_exact(fd, pack("!i", len(config)),
                    "could not write guest state file: config len")
        write_exact(fd, config, "could not write guest state file: config")

        # xc_save takes three customization parameters: maxit, max_f, and
        # flags the last controls whether or not save is 'live', while the
        # first two further customize behaviour when 'live' save is
        # enabled. Passing "0" simply uses the defaults compiled into
        # libxenguest; see the comments and/or code in xc_linux_save() for
        # more information.
        cmd = [PATH_XC_SAVE, str(xc.handle()), str(fd),
               str(dominfo.getDomid()), "0", "0", str(int(live)) ]
        log.debug("[xc_save]: %s", string.join(cmd))

        def saveInputHandler(line, tochild):
            log.debug("In saveInputHandler %s", line)
            if line == "suspend":
                log.debug("Suspending %d ...", dominfo.getDomid())
                dominfo.shutdown('suspend')
                dominfo.waitForShutdown()
                log.info("Domain %d suspended.", dominfo.getDomid())
                tochild.write("done\n")
                tochild.flush()

        forkHelper(cmd, fd, saveInputHandler, False)

        dominfo.destroyDomain()

    except Exception, exn:
        log.exception("Save failed on domain %s (%d).", domain_name,
                      dominfo.getDomid())
        try:
            if live:
                dominfo.setName(domain_name)
        except:
            log.exception("Failed to reset the migrating domain's name")
        raise Exception, exn


def restore(xd, fd):
    signature = read_exact(fd, len(SIGNATURE),
        "not a valid guest state file: signature read")
    if signature != SIGNATURE:
        raise XendError("not a valid guest state file: found '%s'" %
                        signature)

    l = read_exact(fd, sizeof_int,
                   "not a valid guest state file: config size read")
    vmconfig_size = unpack("!i", l)[0]
    vmconfig_buf = read_exact(fd, vmconfig_size,
        "not a valid guest state file: config read")

    p = sxp.Parser()
    p.input(vmconfig_buf)
    if not p.ready:
        raise XendError("not a valid guest state file: config parse")

    vmconfig = p.get_val()

    dominfo = xd.restore_(vmconfig)

    assert dominfo.store_channel
    assert dominfo.console_channel

    try:
        l = read_exact(fd, sizeof_unsigned_long,
                       "not a valid guest state file: pfn count read")
        nr_pfns = unpack("=L", l)[0]   # XXX endianess
        if nr_pfns > 1024*1024:     # XXX
            raise XendError(
                "not a valid guest state file: pfn count out of range")

        store_evtchn = dominfo.store_channel.port2
        console_evtchn = dominfo.console_channel.port2

        cmd = [PATH_XC_RESTORE, str(xc.handle()), str(fd),
               str(dominfo.getDomid()), str(nr_pfns),
               str(store_evtchn), str(console_evtchn)]
        log.debug("[xc_restore]: %s", string.join(cmd))

        def restoreInputHandler(line, _):
            m = re.match(r"^(store-mfn) (\d+)$", line)
            if m:
                store_mfn = int(m.group(2))
                dominfo.setStoreRef(store_mfn)
                IntroduceDomain(dominfo.getDomid(),
                                store_mfn,
                                dominfo.store_channel.port1,
                                dominfo.getDomainPath())
            else:
                m = re.match(r"^(console-mfn) (\d+)$", line)
                if m:
                    dominfo.setConsoleRef(int(m.group(2)))

        forkHelper(cmd, fd, restoreInputHandler, True)

        return dominfo
    except:
        dominfo.destroy()
        raise


def forkHelper(cmd, fd, inputHandler, closeToChild):
    child = xPopen3(cmd, True, -1, [fd, xc.handle()])

    if closeToChild:
        child.tochild.close()

    fds = [child.fromchild.fileno(),
           child.childerr.fileno()]
    p = select.poll()
    map(p.register, fds)
    while len(fds) > 0:
        r = p.poll()
        for (fd, event) in r:
            if event & select.POLLHUP or event & select.POLLERR:
                fds.remove(fd)
                p.unregister(fd)
                continue
            if not event & select.POLLIN:
                continue
            if fd == child.childerr.fileno():
                lasterr = child.childerr.readline().rstrip()
                log.error('%s', lasterr)
            else:
                l = child.fromchild.readline().rstrip()
                while l:
                    log.debug('%s', l)
                    inputHandler(l, child.tochild)
                    try:
                        l = child.fromchild.readline().rstrip()
                    except:
                        l = None

    child.fromchild.close()
    child.childerr.close()

    if child.wait() >> 8 == 127:
        lasterr = "popen failed"
    if child.wait() != 0:
        raise XendError("%s failed: %s" % (string.join(cmd), lasterr))
