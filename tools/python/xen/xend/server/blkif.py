# Copyright (C) 2004 Mike Wray <mike.wray@hp.com>
"""Support for virtual block devices.
"""

from twisted.internet import defer

from xen.xend import sxp
from xen.xend.XendLogging import log
from xen.xend.XendError import XendError

import channel
import controller
from messages import *

class BlkifBackendController(controller.BackendController):
    """ Handler for the 'back-end' channel to a block device driver domain.
    """

    def __init__(self, factory, dom):
        controller.BackendController.__init__(self, factory, dom)
        self.addMethod(CMSG_BLKIF_BE,
                       CMSG_BLKIF_BE_DRIVER_STATUS,
                       self.recv_be_driver_status)
        self.registerChannel()

    def recv_be_driver_status(self, msg, req):
        """Request handler for be_driver_status messages.
        
        @param msg: message
        @type  msg: xu message
        @param req: request flag (true if the msg is a request)
        @type  req: bool
        """
        val = unpackMsg('blkif_be_driver_status_t', msg)
        status = val['status']

class BlkifBackendInterface(controller.BackendInterface):
    """ Handler for the 'back-end' channel to a block device driver domain
    on behalf of a front-end domain.
    Must be connected using connect() before it can be used.
    Do not create directly - use getBackendInterface() on the BlkifController.
    """

    def __init__(self, ctrl, dom, handle):
        controller.BackendInterface.__init__(self, ctrl, dom, handle)
        self.connected = 0
        self.evtchn = None
        self.status = BLKIF_INTERFACE_STATUS_DISCONNECTED

    def __str__(self):
        return '<BlkifBackendInterface %d %d>' % (self.controller.dom, self.dom)

    def getEventChannelBackend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port1']
        return val

    def getEventChannelFrontend(self):
        val = 0
        if self.evtchn:
            val = self.evtchn['port2']
        return val

    def connect(self, recreate=0):
        """Connect to the blkif control interface.

        @param recreate: true if after xend restart
        @return: deferred
        """
        log.debug("Connecting blkif %s", str(self))
        if recreate or self.connected:
            d = defer.succeed(self)
        else:
            d = self.send_be_create()
            d.addCallback(self.respond_be_create)
        return d
        
    def send_be_create(self):
        d = defer.Deferred()
        msg = packMsg('blkif_be_create_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=d)
        return d

    def respond_be_create(self, msg):
        val = unpackMsg('blkif_be_create_t', msg)
        self.connected = 1
        return self
    
    def destroy(self):
        """Disconnect from the blkif control interface and destroy it.
        """
        def cb_destroy(val):
            self.send_be_destroy()
            self.close()
        d = defer.Deferred()
        d.addCallback(cb_destroy)
        self.send_be_disconnect(response=d)
        
    def send_be_disconnect(self, response=None):
        msg = packMsg('blkif_be_disconnect_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=response)

    def send_be_destroy(self, response=None):
        msg = packMsg('blkif_be_destroy_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle })
        self.writeRequest(msg, response=response)

    def connectInterface(self, val):
        self.evtchn = channel.eventChannel(0, self.controller.dom)
        log.debug("Connecting blkif to event channel %s ports=%d:%d",
                  str(self), self.evtchn['port1'], self.evtchn['port2'])
        msg = packMsg('blkif_be_connect_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : self.handle,
                        'evtchn'       : self.getEventChannelBackend(),
                        'shmem_frame'  : val['shmem_frame'] })
        d = defer.Deferred()
        d.addCallback(self.respond_be_connect)
        self.writeRequest(msg, response=d)

    def respond_be_connect(self, msg):
        """Response handler for a be_connect message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_connect_t', msg)
        self.status = BLKIF_INTERFACE_STATUS_CONNECTED
        self.send_fe_interface_status()
            
    def send_fe_interface_status(self, response=None):
        msg = packMsg('blkif_fe_interface_status_t',
                      { 'handle' : self.handle,
                        'status' : self.status,
                        'domid'  : self.dom,
                        'evtchn' : self.getEventChannelFrontend() })
        self.controller.writeRequest(msg, response=response)

    def interfaceDisconnected(self):
        self.status = BLKIF_INTERFACE_STATUS_DISCONNECTED
        #todo?: Do this: self.evtchn = None
        self.send_fe_interface_status()
        
    def interfaceChanged(self):
        """Notify the front-end that devices have been added or removed.
        The front-end should then probe for devices.
        """
        msg = packMsg('blkif_fe_interface_status_t',
                      { 'handle' : self.handle,
                        'status' : BLKIF_INTERFACE_STATUS,
                        'domid'  : self.dom,
                        'evtchn' : 0 })
        self.controller.writeRequest(msg)
        
class BlkifControllerFactory(controller.SplitControllerFactory):
    """Factory for creating block device interface controllers.
    """

    def __init__(self):
        controller.SplitControllerFactory.__init__(self)

    def createController(self, dom, recreate=0):
        """Create a block device controller for a domain.

        @param dom: domain
        @type  dom: int
        @param recreate: if true it's a recreate (after xend restart)
        @type  recreate: bool
        @return: block device controller
        @rtype: BlkifController
        """
        blkif = self.getControllerByDom(dom)
        if blkif is None:
            blkif = BlkifController(self, dom)
            self.addController(blkif)
        return blkif

    def createBackendController(self, dom):
        """Create a block device backend controller.

        @param dom: backend domain
        @return: backend controller
        """
        return BlkifBackendController(self, dom)

    def createBackendInterface(self, ctrl, dom, handle):
        """Create a block device backend interface.

        @param ctrl: controller
        @param dom: backend domain
        @param handle: interface handle
        @return: backend interface
        """
        return BlkifBackendInterface(ctrl, dom, handle)

    def getDomainDevices(self, dom):
        """Get the block devices for a domain.

        @param dom: domain
        @type  dom: int
        @return: devices
        @rtype:  [device]
        """
        blkif = self.getControllerByDom(dom)
        return (blkif and blkif.getDevices()) or []

    def getDomainDevice(self, dom, idx):
        """Get a block device from a domain.

        @param dom: domain
        @type  dom: int
        @param idx: device index
        @type  idx: int
        @return: device
        @rtype:  device
        """
        blkif = self.getControllerByDom(dom)
        return (blkif and blkif.getDevice(idx)) or None

class BlkDev(controller.SplitDev):
    """Info record for a block device.
    """

    def __init__(self, idx, ctrl, config, vdev, mode, segment):
        controller.SplitDev.__init__(self, idx, ctrl)
        self.config = config
        self.dev = None
        self.uname = None
        self.vdev = vdev
        self.mode = mode
        self.device = segment['device']
        self.start_sector = segment['start_sector']
        self.nr_sectors = segment['nr_sectors']
        try:
            self.backendDomain = int(sxp.child_value(config, 'backend', '0'))
        except:
            raise XendError('invalid backend domain')

    def readonly(self):
        return 'w' not in self.mode

    def sxpr(self):
        val = ['blkdev',
               ['idx', self.idx],
               ['vdev', self.vdev],
               ['device', self.device],
               ['mode', self.mode]]
        if self.dev:
            val.append(['dev', self.dev])
        if self.uname:
            val.append(['uname', self.uname])
        return val

    def destroy(self, change=0):
        """Destroy the device. If 'change' is true notify the front-end interface.

        @param change: change flag
        """
        log.debug("Destroying vbd domain=%d idx=%s", self.controller.dom, self.idx)
        d = self.send_be_vbd_destroy()
        if change:
            d.addCallback(lambda val: self.interfaceChanged())

    def interfaceChanged(self):
        """Tell the back-end to notify the front-end that a device has been
        added or removed.
        """
        self.getBackendInterface().interfaceChanged()

    def attach(self):
        """Attach the device to its controller.

        """
        backend = self.getBackendInterface()
        d1 = backend.connect()
        d2 = defer.Deferred()
        d2.addCallback(self.send_be_vbd_create)
        d1.chainDeferred(d2)
        return d2
        
    def send_be_vbd_create(self, val):
        d = defer.Deferred()
        d.addCallback(self.respond_be_vbd_create)
        backend = self.getBackendInterface()
        msg = packMsg('blkif_be_vbd_create_t',
                      { 'domid'        : self.controller.dom,
                        'blkif_handle' : backend.handle,
                        'vdevice'      : self.vdev,
                        'readonly'     : self.readonly() })
        backend.writeRequest(msg, response=d)
        return d
        
    def respond_be_vbd_create(self, msg):
        """Response handler for a be_vbd_create message.
        Tries to grow the vbd.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_vbd_create_t', msg)
        d = self.send_be_vbd_grow()
        d.addCallback(self.respond_be_vbd_grow)
        return d
    
    def send_be_vbd_grow(self):
        d = defer.Deferred()
        backend = self.getBackendInterface()
        msg = packMsg('blkif_be_vbd_grow_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : backend.handle,
                        'vdevice'              : self.vdev,
                        'extent.device'        : self.device,
                        'extent.sector_start'  : self.start_sector,
                        'extent.sector_length' : self.nr_sectors })
        backend.writeRequest(msg, response=d)
        return d

    def respond_be_vbd_grow(self, msg):
        """Response handler for a be_vbd_grow message.

        @param msg: message
        @type  msg: xu message
        """
        val = unpackMsg('blkif_be_vbd_grow_t', msg)
	status = val['status']
	if status != BLKIF_BE_STATUS_OKAY:
            raise XendError("Adding extent to vbd failed: device %d, error %d"
                            % (self.vdev, status))
        return self

    def send_be_vbd_destroy(self):
        d = defer.Deferred()
        backend = self.getBackendInterface()
        msg = packMsg('blkif_be_vbd_destroy_t',
                      { 'domid'                : self.controller.dom,
                        'blkif_handle'         : backend.handle,
                        'vdevice'              : self.vdev })
        self.controller.delDevice(self.vdev)
        backend.writeRequest(msg, response=d)
        return d
        
        
class BlkifController(controller.SplitController):
    """Block device interface controller. Handles all block devices
    for a domain.
    """
    
    def __init__(self, factory, dom):
        """Create a block device controller.
        Do not call directly - use createController() on the factory instead.
        """
        controller.SplitController.__init__(self, factory, dom)
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_DRIVER_STATUS,
                       self.recv_fe_driver_status)
        self.addMethod(CMSG_BLKIF_FE,
                       CMSG_BLKIF_FE_INTERFACE_CONNECT,
                       self.recv_fe_interface_connect)
        self.registerChannel()

    def sxpr(self):
        val = ['blkif', ['dom', self.dom]]
        return val

    def addDevice(self, idx, config, vdev, mode, segment):
        """Add a device to the device table.

        @param vdev:     device index
        @type  vdev:     int
        @param mode:     read/write mode
        @type  mode:     string
        @param segment:  segment
        @type  segment:  int
        @return: device
        @rtype:  BlkDev
        """
        if idx in self.devices:
            raise XendError('device exists: ' + str(idx))
        dev = BlkDev(idx, self, config, vdev, mode, segment)
        self.devices[idx] = dev
        return dev

    def attachDevice(self, idx, config, vdev, mode, segment, recreate=0):
        """Attach a device to the specified interface.
        On success the returned deferred will be called with the device.

        @param idx:      device id
        @param config:   device configuration
        @param vdev:     device index
        @type  vdev:     int
        @param mode:     read/write mode
        @type  mode:     string
        @param segment:  segment
        @type  segment:  int
        @param recreate: if true it's being recreated (after xend restart)
        @type  recreate: bool
        @return: deferred
        @rtype:  Deferred
        """
        dev = self.addDevice(idx, config, vdev, mode, segment)
        if recreate:
            d = defer.succeed(dev)
        else:
            d = dev.attach()
        return d

    def destroy(self):
        """Destroy the controller and all devices.
        """
        log.debug("Destroying blkif domain=%d", self.dom)
        self.destroyDevices()
        self.destroyBackends()

    def destroyDevices(self):
        """Destroy all devices.
        """
        for dev in self.getDevices():
            dev.destroy()

    def destroyBackends(self):
        for backend in self.getBackendInterfaces():
            backend.destroy()

    def recv_fe_driver_status(self, msg, req):
        val = unpackMsg('blkif_fe_driver_status_t', msg)
        print 'recv_fe_driver_status>', val
        for backend in self.getBackendInterfaces():
            backend.interfaceDisconnected()

    def recv_fe_interface_connect(self, msg, req):
        val = unpackMsg('blkif_fe_interface_connect_t', msg)
        handle = val['handle']
        backend = self.getBackendInterfaceByHandle(handle)
        if backend:
            backend.connectInterface(val)
        else:
            log.error('interface connect on unknown interface: handle=%d', handle)


    

