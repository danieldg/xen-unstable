# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>

"""Handler for domain operations.
 Nothing here is persistent (across reboots).
 Needs to be persistent for one uptime.
"""
import sys
import traceback

from twisted.internet import defer
#defer.Deferred.debug = 1
from twisted.internet import reactor

import xen.lowlevel.xc; xc = xen.lowlevel.xc.new()

import sxp
import XendRoot
xroot = XendRoot.instance()
import XendDB
import XendDomainInfo
import XendConsole
import XendMigrate
import EventServer

from xen.xend.server import SrvDaemon
xend = SrvDaemon.instance()

eserver = EventServer.instance()

__all__ = [ "XendDomain" ]
        
class XendDomain:
    """Index of all domains. Singleton.
    """

    """Path to domain database."""
    dbpath = "domain"

    """Table of domain info indexed by domain id."""
    domain = {}
    
    """Table of configs for domain restart, indexed by domain id."""
    restarts = {}

    """Table of delayed calls."""
    schedule = {}
    
    def __init__(self):
        self.xconsole = XendConsole.instance()
        # Table of domain info indexed by domain id.
        self.db = XendDB.XendDB(self.dbpath)
        self.domain_db = self.db.fetchall("")
        if xroot.get_rebooted():
            print 'XendDomain> rebooted: removing all domain info'
            self.rm_all()
        eserver.subscribe('xend.virq', self.onVirq)
        self.initial_refresh()

    def onVirq(self, event, val):
        """Event handler for virq.
        """
        print 'XendDomain> virq', val
        self.reap()

    def schedule_later(self, _delay, _name, _fn, *args):
        """Schedule a function to be called later (if not already scheduled).

        _delay delay in seconds
        _name  schedule name
        _fn    function
        args   arguments
        """
        if self.schedule.get(_name): return
        self.schedule[_name] = reactor.callLater(_delay, _fn, *args)
        
    def schedule_cancel(self, name):
        """Cancel a scheduled function call.
        
        name schedule name to cancel
        """
        callid = self.schedule.get(name)
        if not callid:
            return
        if callid.active():
            callid.cancel()
        del self.schedule[name]

    def reap_schedule(self, delay=0):
        """Schedule reap to be called later.

        delay delay in seconds
        """
        self.schedule_later(delay, 'reap', self.reap)

    def reap_cancel(self):
        """Cancel any scheduled reap.
        """
        self.schedule_cancel('reap')

    def refresh_schedule(self, delay=0):
        """Schedule refresh to be called later.
        
        delay delay in seconds
        """
        self.schedule_later(delay, 'refresh', self.refresh)

    def refresh_cancel(self):
        """Cancel any scheduled refresh.
        """
        self.schedule_cancel('refresh')

    def rm_all(self):
        """Remove all domain info. Used after reboot.
        """
        for (k, v) in self.domain_db.items():
            self._delete_domain(k, notify=0)
            
    def initial_refresh(self):
        """Refresh initial domain info from domain_db.
        """
        print "initial_refresh>"
        for d in self.domain_db.values(): print 'db dom=', d
        domlist = xc.domain_getinfo()
        for d in domlist: print 'xc dom=', d
        doms = {}
        for d in domlist:
            domid = str(d['dom'])
            doms[domid] = d
        dlist = []
        for config in self.domain_db.values():
            domid = str(sxp.child_value(config, 'id'))
            print "dom=", domid, "config=", config
            if domid in doms:
                print "dom=", domid, "new"
                deferred = self._new_domain(config, doms[domid])
                dlist.append(deferred)
            else:
                print "dom=", domid, "del"
                self._delete_domain(domid)
        deferred = defer.DeferredList(dlist, fireOnOneErrback=1)
        def cbok(val):
            #print "doms:"
            #for d in self.domain.values(): print 'dom', d
            self.refresh()
            print "XendDomain>initial_refresh> doms:"
            for d in self.domain.values(): print 'dom', d
        deferred.addCallback(cbok)

    def sync(self):
        """Sync domain db to disk.
        """
        self.db.saveall("", self.domain_db)

    def sync_domain(self, dom):
        """Sync info for a domain to disk.

        dom	domain id (string)
        """
        self.db.save(dom, self.domain_db[dom])

    def close(self):
        pass

    def _new_domain(self, savedinfo, info):
        """Create a domain entry from saved info.

        savedinfo saved info from the db
        info      domain info from xen

        returns deferred
        """
        config = sxp.child_value(savedinfo, 'config')
        deferred = XendDomainInfo.vm_recreate(config, info)
        def fn(dominfo):
            self.domain[dominfo.id] = dominfo
        deferred.addCallback(fn)
        return deferred

    def _add_domain(self, id, info, notify=1):
        """Add a domain entry to the tables.

        id     domain id
        info   domain info object
        notify send a domain created event if true
        """
        self.domain[id] = info
        self.domain_db[id] = info.sxpr()
        self.sync_domain(id)
        if notify: eserver.inject('xend.domain.created', id)

    def _delete_domain(self, id, notify=1):
        """Remove a domain from the tables.

        id     domain id
        notify send a domain died event if true
        """
        if id in self.domain:
            if notify: eserver.inject('xend.domain.died', id)
            del self.domain[id]
        if id in self.domain_db:
            del self.domain_db[id]
            self.db.delete(id)

    def reap(self):
        """Look for domains that have crashed or stopped.
        Tidy them up.
        """
        self.reap_cancel()
        print 'XendDomain>reap>'
        domlist = xc.domain_getinfo()
        casualties = []
        for d in domlist:
            dead = 0
            dead = dead or (d['crashed'] or d['shutdown'])
            dead = dead or (d['dying'] and
                            not(d['running'] or d['paused'] or d['blocked']))
            if dead:
                casualties.append(d)
        for d in casualties:
            id = str(d['dom'])
            print 'XendDomain>reap> died id=', id, d
            self.final_domain_destroy(id)
        print 'XendDomain>reap<'

    def refresh(self):
        """Refresh domain list from Xen.
        """
        self.refresh_cancel()
        print 'XendDomain>refresh>'
        domlist = xc.domain_getinfo()
        # Index the domlist by id.
        # Add entries for any domains we don't know about.
        doms = {}
        for d in domlist:
            id = str(d['dom'])
            doms[id] = d
            if id not in self.domain:
                config = None
                deferred = XendDomainInfo.vm_recreate(config, d)
                def fn(dominfo):
                    self._add_domain(dominfo.id, dominfo)
                deferred.addCallback(fn)
        # Remove entries for domains that no longer exist.
        for d in self.domain.values():
            dominfo = doms.get(d.id)
            if dominfo:
                d.update(dominfo)
            else:
                self._delete_domain(d.id)
        self.reap_schedule(1)

    def refresh_domain(self, id):
        """Refresh information for a single domain.

        id domain id
        """
        dom = int(id)
        dominfo = xc.domain_getinfo(dom, 1)
        if dominfo == [] or dominfo[0]['dom'] != dom:
            try:
                self._delete_domain(id)
            except:
                print 'refresh_domain: error'
                raise
                pass
        else:
            d = self.domain.get(id)
            if d:
                d.update(dominfo[0])

    def domain_ls(self):
        """Get list of domain ids.

        return domain ids
        """
        self.refresh()
        return self.domain.keys()

    def domains(self):
        """Get list of domain objects.

        return domain objects
        """
        self.refresh()
        return self.domain.values()
    
    def domain_create(self, config):
        """Create a domain from a configuration.

        config configuration

        returns deferred
        """
        deferred = XendDomainInfo.vm_create(config)
        def fn(dominfo):
            self._add_domain(dominfo.id, dominfo)
            return dominfo
        deferred.addCallback(fn)
        return deferred
    
    def domain_get(self, id):
        """Get up-to-date info about a domain.

        id domain id
        returns domain object (or None)
        """
        id = str(id)
        self.refresh_domain(id)
        return self.domain.get(id)
    
    def domain_unpause(self, id):
        """Unpause domain execution.

        id domain id
        """
        dom = int(id)
        eserver.inject('xend.domain.unpause', id)
        return xc.domain_unpause(dom=dom)
    
    def domain_pause(self, id):
        """Pause domain execution.

        id domain id
        """
        dom = int(id)
        eserver.inject('xend.domain.pause', id)
        return xc.domain_pause(dom=dom)
    
    def domain_shutdown(self, id, reason='poweroff'):
        """Shutdown domain (nicely).

        id     domain id
        reason shutdown type: poweroff, reboot, suspend, halt
        """
        dom = int(id)
        if dom <= 0:
            return 0
        self.domain_restart_schedule(id, reason)
        eserver.inject('xend.domain.shutdown', [id, reason])
        if reason == 'halt':
            reason = 'poweroff'
        val = xend.domain_shutdown(dom, reason)
        self.refresh_schedule()
        return val

    def domain_restart_schedule(self, id, reason):
        """Schedule a restart for a domain if it needs one.

        id     domain id
        reason shutdown reason
        """
        if id in self.restarts:
            # Don't schedule if already there.
            return
        restart = 0
        if reason in ['poweroff', 'reboot']:
            dominfo = self.domain.get(id)
            if dominfo and (dominfo.autorestart or reason == 'reboot'):
                restart = 1
                # Clear autorestart flag to avoid multiple restarts.
                dominfo.autorestart = 0
            
        if restart:
            self.restarts[id] = dominfo.config
            
    def domain_restart_cancel(self, id):
        """Cancel any restart scheduled for a domain.

        id domain id
        """
        dominfo = self.domain.get(id)
        if dominfo:
            dominfo.autorestart = 0
        if id in self.restarts:
            del self.restarts[id]

    def domain_restarts(self):
        """Execute any scheduled domain restarts for domains that have gone.
        """
        for id in self.restarts.keys():
            if id in self.domain:
                # Don't execute restart for domains still running.
                continue
            config = self.restarts[id]
            # Remove it from the restarts.
            del self.restarts[id]
            try:
                self.domain_create(config)
            except:
                print >>sys.stderr, "XendDomain> Exception restarting domain"
                traceback.print_exc(sys.stderr)
        
    def final_domain_destroy(self, id):
        """Final destruction of a domain..

        id domain id
        """
        dom = int(id)
        if dom <= 0:
            return 0
        eserver.inject('xend.domain.destroy', id)
        dominfo = self.domain.get(id)
        if dominfo:
            val = dominfo.destroy()
        else:
            val = xc.domain_destroy(dom=dom)
        return val       

    def domain_destroy(self, id):
        """Terminate domain immediately.
        Camcels any restart for the domain.

        id domain id
        """
        self.domain_restart_cancel(id)
        val = self.final_domain_destroy(id)
        self.refresh_schedule()
        return val

    def domain_migrate(self, id, dst):
        """Start domain migration.

        id domain id
        """
        # Need a cancel too?
        # Don't forget to cancel restart for it.
        dom = int(id)
        xmigrate = XendMigrate.instance()
        return xmigrate.migrate_begin(dom, dst)

    def domain_save(self, id, dst, progress=0):
        """Save domain state to file, destroy domain on success.
        Leave domain running on error.

        id       domain id
        dst      destination file
        progress output progress if true
        """
        dom = int(id)
        dominfo = self.domain_get(id)
        if not dominfo:
            return -1
        vmconfig = sxp.to_string(dominfo.sxpr())
        self.domain_pause(id)
        eserver.inject('xend.domain.save', id)
        try:
            rc = xc.linux_save(dom=dom, state_file=dst,
                               vmconfig=vmconfig, progress=progress)
        except:
            rc = -1
        if rc == 0:
            self.domain_destroy(id)
        else:
            self.domain_unpause(id)
        return rc
    
    def domain_restore(self, src, progress=0):
        """Restore domain from file.

        src      source file
        progress output progress if true

        returns domain object
        """
        dominfo = XendDomainInfo.vm_restore(src, progress=progress)
        self._add_domain(dominfo.id, dominfo)
        return dominfo
    
    def domain_pincpu(self, dom, cpu):
        """Pin a domain to a cpu.

        dom domain
        cpu cpu number
        """
        dom = int(dom)
        return xc.domain_pincpu(dom, cpu)

    def domain_cpu_bvt_set(self, dom, mcuadv, warp, warpl, warpu):
        """Set BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.bvtsched_domain_set(dom=dom, mcuadv=mcuadv,
                                      warp=warp, warpl=warpl, warpu=warpu)

    def domain_cpu_bvt_get(self, dom):
        """Get BVT (Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.bvtsched_domain_get(dom)
    
    def domain_cpu_fbvt_set(self, dom, mcuadv, warp, warpl, warpu):
        """Set FBVT (Fair Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.fbvtsched_domain_set(dom=dom, mcuadv=mcuadv,
                                      warp=warp, warpl=warpl, warpu=warpu)

    def domain_cpu_fbvt_get(self, dom):
        """Get FBVT (Fair Borrowed Virtual Time) scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.fbvtsched_domain_get(dom)
        
    def domain_cpu_atropos_set(self, dom, period, slice, latency, xtratime):
        """Set Atropos scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.atropos_domain_set(dom, period, slice, latency, xtratime)

    def domain_cpu_atropos_get(self, dom):
        """Get Atropos scheduler parameters for a domain.
        """
        dom = int(dom)
        return xc.atropos_domain_get(dom)

    def domain_devtype_ls(self, dom, type):
        """Get list of device indexes for a domain.

        dom  domain
        type device type

        returns device indexes
        """
        dominfo = self.domain_get(dom)
        if not dominfo: return None
        devs = dominfo.get_devices(type)
        return range(0, len(devs))

    def domain_devtype_get(self, dom, type, idx):
        """Get a device from a domain.

        dom  domain
        type device type
        idx  device index

        returns device object (or None)
        """
        dominfo = self.domain_get(dom)
        if not dominfo: return None
        return dominfo.get_device_by_index(type, idx)

    def domain_vif_ls(self, dom):
        """Get list of virtual network interface (vif) indexes for a domain.

        dom domain

        returns vif indexes
        """
        return self.domain_devtype_ls(dom, 'vif')

    def domain_vif_get(self, dom, vif):
        """Get a virtual network interface (vif) from a domain.

        dom domain
        vif vif index

        returns vif device object (or None)
        """
        return self.domain_devtype_get(dom, 'vif', vif)

    def domain_vbd_ls(self, dom):
        """Get list of virtual block device (vbd) indexes for a domain.

        dom domain

        returns vbd indexes
        """
        return self.domain_devtype_ls(dom, 'vbd')

    def domain_vbd_get(self, dom, vbd):
        """Get a virtual block device (vbd) from a domain.

        dom domain
        vbd vbd index

        returns vbd device (or None)
        """
        return self.domain_devtype_get(dom, 'vbd', vbd)

    def domain_shadow_control(self, dom, op):
        """Shadow page control.

        dom domain
        op  operation
        """
        dom = int(dom)
        return xc.shadow_control(dom, op)


def instance():
    """Singleton constructor. Use this instead of the class constructor.
    """
    global inst
    try:
        inst
    except:
        inst = XendDomain()
    return inst
