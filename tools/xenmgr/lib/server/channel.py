import Xc; xc = Xc.new()
import xend.utils
from messages import msgTypeName

def eventChannel(dom1, dom2):
    return xc.evtchn_bind_interdomain(dom1=dom1, dom2=dom2)

class ChannelFactory:
    """Factory for creating channels.
    Maintains a table of channels.
    """
    
    channels = {}

    def __init__(self):
        self.notifier = xend.utils.notifier()
    
    def addChannel(self, channel):
        idx = channel.idx
        self.channels[idx] = channel
        self.notifier.bind(idx)
        # Try to wake it up
        #self.notifier.unmask(idx)
        #channel.notify()

    def getChannel(self, idx):
        return self.channels.get(idx)

    def delChannel(self, idx):
        if idx in self.channels:
            del self.channels[idx]
            self.notifier.unbind(idx)

    def domChannel(self, dom):
        for chan in self.channels.values():
            if chan.dom == dom:
                return chan
        chan = Channel(self, dom)
        self.addChannel(chan)
        return chan

    def channelClosed(self, channel):
        self.delChannel(channel.idx)

    def createPort(self, dom):
        return xend.utils.port(dom)

def channelFactory():
    global inst
    try:
        inst
    except:
        inst = ChannelFactory()
    return inst

class Channel:
    """A control channel to a domain. Messages for the domain device controllers
    are multiplexed over the channel (console, block devs, net devs).
    """

    def __init__(self, factory, dom):
        self.factory = factory
        self.dom = dom
        self.port = self.factory.createPort(dom)
        self.idx = self.port.local_port
        self.devs = []
        self.devs_by_type = {}
        self.closed = 0
        self.queue = []

    def getIndex(self):
        return self.idx

    def getLocalPort(self):
        return self.port.local_port

    def getRemotePort(self):
        return self.port.remote_port

    def close(self):
        for d in self.devs:
            d.lostChannel()
        self.factory.channelClosed(self)
        del self.devs
        del self.devs_by_type

    def registerDevice(self, types, dev):
        """Register a device controller.

        @param types message types the controller handles
        @param dev   device controller
        """
        self.devs.append(dev)
        for ty in types:
            self.devs_by_type[ty] = dev

    def unregisterDevice(self, dev):
        """Remove the registration for a device controller.

        @param dev device controller
        """
        self.devs.remove(dev)
        types = [ ty for (ty, d) in self.devs_by_type.items()
                  if d == dev ]
        for ty in types:
            del devs_by_type[ty]

    def getDevice(self, type):
        """Get the device controller handling a message type.

        @param type message type
        @returns controller or None
        """
        return self.devs_by_type.get(type)

    def getMessageType(self, msg):
        hdr = msg.get_header()
        return (hdr['type'], hdr.get('subtype'))

    def __repr__(self):
        return ('<Channel dom=%d ports=%d:%d>'
                % (self.dom,
                   self.port.local_port,
                   self.port.remote_port))

    def notificationReceived(self, type):
        #print 'notificationReceived> type=', type, self
        if self.closed: return
        if type == self.factory.notifier.EXCEPTION:
            print 'notificationReceived> EXCEPTION'
            info = xc.evtchn_status(self.idx)
            if info['status'] == 'unbound':
                print 'notificationReceived> EXCEPTION closing...'
                self.close()
                return
        work = 0
        work += self.handleRequests()
        work += self.handleResponses()
        work += self.handleWrites()
        if work:
            self.notify()
        #print 'notificationReceived<', work

    def notify(self):
        #print 'notify>', self
        self.port.notify()

    def handleRequests(self):
        #print 'handleRequests>'
        work = 0
        while 1:
            #print 'handleRequests>', work
            msg = self.readRequest()
            #print 'handleRequests> msg=', msg
            if not msg: break
            self.requestReceived(msg)
            work += 1
        #print 'handleRequests<', work
        return work

    def requestReceived(self, msg):
        (ty, subty) = self.getMessageType(msg)
        #print 'requestReceived>', ty, subty, self
        #todo:  Must respond before writing any more messages.
        #todo:  Should automate this (respond on write)
        self.port.write_response(msg)
        dev = self.getDevice(ty)
        if dev:
            dev.requestReceived(msg, ty, subty)
        else:
            print ("requestReceived> No device: Message type %s %d:%d"
                   % (msgTypeName(ty, subty), ty, subty)), self

    def handleResponses(self):
        #print 'handleResponses>', self
        work = 0
        while 1:
            #print 'handleResponses>', work
            msg = self.readResponse()
            #print 'handleResponses> msg=', msg
            if not msg: break
            self.responseReceived(msg)
            work += 1
        #print 'handleResponses<', work
        return work

    def responseReceived(self, msg):
        (ty, subty) = self.getMessageType(msg)
        #print 'responseReceived>', ty, subty
        dev = self.getDevice(ty)
        if dev:
            dev.responseReceived(msg, ty, subty)
        else:
            print ("responseReceived> No device: Message type %d:%d"
                   % (msgTypeName(ty, subty), ty, subty)), self

    def handleWrites(self):
        #print 'handleWrites>', self
        work = 0
        # Pull data from producers.
        #print 'handleWrites> pull...'
        for dev in self.devs:
            work += dev.produceRequests()
        # Flush the queue.
        #print 'handleWrites> flush...'
        while self.queue and self.port.space_to_write_request():
            msg = self.queue.pop(0)
            self.port.write_request(msg)
            work += 1
        #print 'handleWrites<', work
        return work

    def writeRequest(self, msg, notify=1):
        #print 'writeRequest>', self
        if self.closed:
            val = -1
        elif self.writeReady():
            self.port.write_request(msg)
            if notify: self.notify()
            val = 1
        else:
            self.queue.append(msg)
            val = 0
        #print 'writeRequest<', val
        return val

    def writeResponse(self, msg):
        #print 'writeResponse>', self
        if self.closed: return -1
        self.port.write_response(msg)
        return 1

    def writeReady(self):
        if self.closed or self.queue: return 0
        return self.port.space_to_write_request()

    def readRequest(self):
        #print 'readRequest>', self
        if self.closed:
            #print 'readRequest> closed'
            return None
        if self.port.request_to_read():
            val = self.port.read_request()
        else:
            val = None
        #print 'readRequest< ', val
        return val
        
    def readResponse(self):
        #print 'readResponse>', self
        if self.closed:
            #print 'readResponse> closed'
            return None
        if self.port.response_to_read():
            val = self.port.read_response()
        else:
            val = None
        #print 'readResponse<', val
        return val
