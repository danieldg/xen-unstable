# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Support for virtual network interfaces.
"""

import random

from twisted.internet import defer

from xen.xend import sxp
from xen.xend import Vifctl
from xen.xend.XendError import XendError
from xen.xend.XendLogging import log
from xen.xend import XendVnet
from xen.xend.XendRoot import get_component

import channel
import controller
from messages import *

class NetifBackendController(controller.BackendController):
    """Handler for the 'back-end' channel to a network device driver domain.
    """
    
    def __init__(self, ctrl, dom):
        controller.BackendController.__init__(self, ctrl, dom)
        self.addMethod(CMSG_NETIF_BE,
                       CMSG_NETIF_BE_DRIVER_STATUS_CHANGED,
                       self.recv_be_driver_status_changed)
        self.registerChannel()

    def recv_be_driver_status_changed(self, msg, req):
        val = unpackMsg('netif_be_driver_status_changed_t', msg)
        status = val['status']

class NetifBackendInterface(controller.BackendInterface):
    """Handler for the 'back-end' channel to a network device driver domain
    on behalf of a front-end domain.

    Each network device is handled separately, so we add no functionality
    here.
    """

    pass

class NetifControllerFactory(controller.SplitControllerFactory):
    """Factory for creating network interface controllers.
    """

    def __init__(self):
        controller.SplitControllerFactory.__init__(self)

    def createController(self, dom):
        """Create a network interface controller for a domain.

        @param dom:      domain
        @return: netif controller
        """
        return NetifController(self, dom)

    def createBackendController(self, dom):
        """Create a network device backend controller.

        @param dom: backend domain
        @return: backend controller
        """
        return NetifBackendController(self, dom)
    
    def createBackendInterface(self, ctrl, dom, handle):
        """Create a network device backend interface.

        @param ctrl: controller
        @param dom: backend domain
        @param handle: interface handle
        @return: backend interface
        """
        return NetifBackendInterface(ctrl, dom, handle)

    def getDomainDevices(self, dom):
        """Get the network devices for a domain.

        @param dom:  domain
        @return: netif controller list
        """
        netif = self.getControllerByDom(dom)
        return (netif and netif.getDevices()) or []

    def getDomainDevice(self, dom, vif):
        """Get a virtual network interface device for a domain.

        @param dom: domain
        @param vif: virtual interface index
        @return: NetDev
        """
        netif = self.getControllerByDom(dom)
        return (netif and netif.getDevice(vif)) or None
        
class NetDev(controller.SplitDev):
    """Info record for a network device.
    """

    def __init__(self, ctrl, vif, config):
        controller.SplitDev.__init__(self, vif, ctrl)
        self.vif = vif
        self.evtchn = None
        self.configure(config)

    def configure(self, config):
        self.config = config
        self.mac = None
        self.bridge = None
        self.script = None
        self.ipaddr = []
        
        vmac = sxp.child_value(config, 'mac')
        if not vmac: raise XendError("invalid mac")
        mac = [ int(x, 16) for x in vmac.split(':') ]
        if len(mac) != 6: raise XendError("invalid mac")
        self.mac = mac

        self.bridge = sxp.child_value(config, 'bridge')
        self.script = sxp.child_value(config, 'script')

        ipaddrs = sxp.children(config, elt='ip')
        for ipaddr in ipaddrs:
            self.ipaddr.append(sxp.child0(ipaddr))
        
        try:
            self.backendDomain = int(sxp.child_value(config, 'backend', '0'))
        except:
            raise XendError('invalid backend domain')

    def sxpr(self):
        vif = str(self.vif)
        mac = self.get_mac()
        val = ['vif',
               ['idx', self.idx],
               ['vif', vif],
               ['mac', mac]]
        if self.bridge:
            val.append(['bridge', self.bridge])
        if self.script:
            val.append(['script', self.script])
        for ip in self.ipaddr:
            val.append(['ip', ip])
        if self.evtchn:
            val.append(['evtchn',
                        self.evtchn['port1'],
                        self.evtchn['port2']])
        return val

    def get_vifname(self):
        """Get the virtual interface device name.
        """
        return "vif%d.%d" % (self.controller.dom, self.vif)

    def get_mac(self):
        """Get the MAC address as a string.
        """
        return ':'.join(map(lambda x: "%02x" % x, self.mac))

    def vifctl_params(self, vmname=None):
        """Get the parameters to pass to vifctl.
        """
        dom = self.controller.dom
        if vmname is None:
            xd = get_component('xen.xend.XendDomain')
            try:
                vm = xd.domain_lookup(dom)
                vmname = vm.name
            except:
                vmname = 'DOM%d' % dom
        return { 'domain': vmname,
                 'vif'   : self.get_vifname(), 
                 'mac'   : self.get_mac(),
                 'bridge': self.bridge,
                 'script': self.script,
                 'ipaddr': self.ipaddr, }

    def vifctl(self, op, vmname=None):
        """Bring the device up or down.
        The vmname is needed when bringing a device up for a new domain because
        the domain is not yet in the table so we can't look its name up.

        @param op: operation name (up, down)
        @param vmname: vmname
        """
        Vifctl.vifctl(op, **self.vifctl_params(vmname=vmname))
        vnet = XendVnet.instance().vnet_of_bridge(self.bridge)
        if vnet:
            vnet.vifctl(op, self.get_vifname(), self.get_mac())

    def attach(self):
        d = self.send_be_create()
        d.addCallback(self.respond_be_create)
        return d

    def send_be_create(self):
        d = defer.Deferred()
        msg = packMsg('netif_be_create_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif,
                        'mac'          : self.mac })
        self.getBackendInterface().writeRequest(msg, response=d)
        return d

    def respond_be_create(self, msg):
        val = unpackMsg('netif_be_create_t', msg)
        return self

    def destroy(self, change=0):
        """Destroy the device's resources and disconnect from the back-end
        device controller. If 'change' is true notify the front-end interface.

        @param change: change flag
        """
        def cb_destroy(val):
            self.send_be_destroy()
            self.getBackendInterface().close()
            if change:
                self.interfaceChanged()
        log.debug("Destroying vif domain=%d vif=%d", self.controller.dom, self.vif)
        self.vifctl('down')
        d = self.send_be_disconnect()
        d.addCallback(cb_destroy)

    def send_be_disconnect(self):
        d = defer.Deferred()
        msg = packMsg('netif_be_disconnect_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif })
        self.getBackendInterface().writeRequest(msg, response=d)
        return d

    def send_be_destroy(self, response=None):
        msg = packMsg('netif_be_destroy_t',
                      { 'domid'        : self.controller.dom,
                        'netif_handle' : self.vif })
        self.controller.delDevice(self.vif)
        self.getBackendInterface().writeRequest(msg, response=response)
    
    def recv_fe_interface_connect(self, val, req):
        if not req: return
        self.evtchn = channel.eventChannel(0, self.controller.dom)
        msg = packMsg('netif_be_connect_t',
                      { 'domid'          : self.controller.dom,
                        'netif_handle'   : self.vif,
                        'evtchn'         : self.evtchn['port1'],
                        'tx_shmem_frame' : val['tx_shmem_frame'],
                        'rx_shmem_frame' : val['rx_shmem_frame'] })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.getBackendInterface().writeRequest(msg, response=d)
        
    def respond_be_connect(self, msg):
        val = unpackMsg('netif_be_connect_t', msg)
        dom = val['domid']
        vif = val['netif_handle']
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : self.vif,
                        'status' : NETIF_INTERFACE_STATUS_CONNECTED,
                        'evtchn' : self.evtchn['port2'],
                        'domid'  : self.backendDomain,
                        'mac'    : self.mac })
        self.controller.writeRequest(msg)

    def attach_fe_device(self):
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : self.vif,
                        'status' : NETIF_INTERFACE_STATUS_DISCONNECTED,
                        'evtchn' : 0,
                        'domid'  : self.backendDomain,
                        'mac'    : self.mac })
        self.controller.writeRequest(msg)

    def interfaceChanged(self):
        """Notify the font-end that a device has been added or removed.
        The front-end should then probe the devices.
        """
        msg = packMsg('netif_fe_interface_status_changed_t',
                      { 'handle' : self.vif,
                        'status' : NETIF_INTERFACE_STATUS_CHANGED,
                        'evtchn' : 0,
                        'domid'  : self.backendDomain,
                        'mac'    : self.mac })
        self.controller.writeRequest(msg)
        
class NetifController(controller.SplitController):
    """Network interface controller. Handles all network devices for a domain.
    """
    
    def __init__(self, factory, dom):
        controller.SplitController.__init__(self, factory, dom)
        self.devices = {}
        self.addMethod(CMSG_NETIF_FE,
                       CMSG_NETIF_FE_DRIVER_STATUS_CHANGED,
                       self.recv_fe_driver_status_changed)
        self.addMethod(CMSG_NETIF_FE,
                       CMSG_NETIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
        self.registerChannel()

    def sxpr(self):
        val = ['netif', ['dom', self.dom]]
        return val
    
    def lostChannel(self):
        """Method called when the channel has been lost.
        """
        controller.Controller.lostChannel(self)

    def getDevices(self):
        """Get a list of the devices.
        """
        return self.devices.values()

    def getDevice(self, vif):
        """Get a device.

        @param vif: device index
        @return: device (or None)
        """
        return self.devices.get(vif)

    def addDevice(self, vif, config):
        """Add a network interface.

        @param vif: device index
        @param config: device configuration 
        @return: device
        """
        if vif in self.devices:
            raise XendError('device exists:' + str(vif))
        dev = NetDev(self, vif, config)
        self.devices[vif] = dev
        return dev

    def delDevice(self, vif):
        if vif in self.devices:
            del self.devices[vif]

    def destroy(self):
        """Destroy the controller and all devices.
        """
        self.destroyDevices()
        
    def destroyDevices(self):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy()

    def attachDevice(self, vif, config, recreate=0):
        """Attach a network device.

        @param vif: interface index
        @param config: device configuration
        @param recreate: recreate flag (true after xend restart)
        @return: deferred
        """
        dev = self.addDevice(vif, config)
        if recreate:
            d = defer.succeed(dev)
        else:
            d = dev.attach()
        return d

    def recv_fe_driver_status_changed(self, msg, req):
        if not req: return
        msg = packMsg('netif_fe_driver_status_changed_t',
                      { 'status'     : NETIF_DRIVER_STATUS_UP,
                        ## FIXME: max_handle should be max active interface id
                        'max_handle' : len(self.devices) })
        self.writeRequest(msg)
        for dev in self.devices.values():
            dev.attach_fe_device()
    
    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('netif_fe_interface_connect_t', msg)
        vif = val['handle']
        dev = self.devices.get(vif)
        if dev:
            dev.recv_fe_interface_connect(val, req)
        else:
            log.error('Received netif_fe_interface_connect for unknown vif: dom=%d vif=%d',
                      self.dom, vif)

