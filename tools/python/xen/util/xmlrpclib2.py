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
# Copyright (C) 2006 Anthony Liguori <aliguori@us.ibm.com>
# Copyright (C) 2006 XenSource Inc.
#============================================================================

"""
An enhanced XML-RPC client/server interface for Python.
"""

import string
import types
import fcntl

from httplib import HTTPConnection, HTTP
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
import SocketServer
import xmlrpclib, socket, os, stat

from xen.xend.XendLogging import log

try:
    import SSHTransport
    ssh_enabled = True
except ImportError:
    # SSHTransport is disabled on Python <2.4, because it uses the subprocess
    # package.
    ssh_enabled = False


# A new ServerProxy that also supports httpu urls.  An http URL comes in the
# form:
#
# httpu:///absolute/path/to/socket.sock
#
# It assumes that the RPC handler is /RPC2.  This probably needs to be improved

# We're forced to subclass the RequestHandler class so that we can work around
# some bugs in Keep-Alive handling and also enabled it by default
class XMLRPCRequestHandler(SimpleXMLRPCRequestHandler):
    protocol_version = "HTTP/1.1"

    # this is inspired by SimpleXMLRPCRequestHandler's do_POST but differs
    # in a few non-trivial ways
    # 1) we never generate internal server errors.  We let the exception
    #    propagate so that it shows up in the Xend debug logs
    # 2) we don't bother checking for a _dispatch function since we don't
    #    use one
    def do_POST(self):
        data = self.rfile.read(int(self.headers["content-length"]))
        rsp = self.server._marshaled_dispatch(data)

        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Content-Length", str(len(rsp)))
        self.end_headers()

        self.wfile.write(rsp)
        self.wfile.flush()
        if self.close_connection == 1:
            self.connection.shutdown(1)

class HTTPUnixConnection(HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.host)

class HTTPUnix(HTTP):
    _connection_class = HTTPUnixConnection

class UnixTransport(xmlrpclib.Transport):
    def request(self, host, handler, request_body, verbose=0):
        self.__handler = handler
        return xmlrpclib.Transport.request(self, host, '/RPC2',
                                           request_body, verbose)
    def make_connection(self, host):
        return HTTPUnix(self.__handler)


# See _marshalled_dispatch below.
def conv_string(x):
    if (isinstance(x, types.StringType) or
        isinstance(x, unicode)):
        s = string.replace(x, "'", r"\047")
        exec "s = '" + s + "'"
        return s
    else:
        return x


class ServerProxy(xmlrpclib.ServerProxy):
    def __init__(self, uri, transport=None, encoding=None, verbose=0,
                 allow_none=1):
        if transport == None:
            (protocol, rest) = uri.split(':', 1)
            if protocol == 'httpu':
                uri = 'http:' + rest
                transport = UnixTransport()
            elif protocol == 'ssh':
                global ssh_enabled
                if ssh_enabled:
                    (transport, uri) = SSHTransport.getHTTPURI(uri)
                else:
                    raise ValueError(
                        "SSH transport not supported on Python <2.4.")
        xmlrpclib.ServerProxy.__init__(self, uri, transport, encoding,
                                       verbose, allow_none)

    def __request(self, methodname, params):
        response = xmlrpclib.ServerProxy.__request(self, methodname, params)

        if isinstance(response, tuple):
            return tuple([conv_string(x) for x in response])
        else:
            return conv_string(response)


# This is a base XML-RPC server for TCP.  It sets allow_reuse_address to
# true, and has an improved marshaller that logs and serializes exceptions.

class TCPXMLRPCServer(SocketServer.ThreadingMixIn, SimpleXMLRPCServer):
    allow_reuse_address = True

    def __init__(self, addr, requestHandler=XMLRPCRequestHandler,
                 logRequests = 1):
        SimpleXMLRPCServer.__init__(self, addr, requestHandler, logRequests)

        flags = fcntl.fcntl(self.fileno(), fcntl.F_GETFD)
        flags |= fcntl.FD_CLOEXEC
        fcntl.fcntl(self.fileno(), fcntl.F_SETFD, flags)

    def get_request(self):
        (client, addr) = SimpleXMLRPCServer.get_request(self)
        flags = fcntl.fcntl(client.fileno(), fcntl.F_GETFD)
        flags |= fcntl.FD_CLOEXEC
        fcntl.fcntl(client.fileno(), fcntl.F_SETFD, flags)
        return (client, addr)
                                                                                
    def _marshaled_dispatch(self, data, dispatch_method = None):
        params, method = xmlrpclib.loads(data)
        if False:
            # Enable this block of code to exit immediately without sending
            # a response.  This allows you to test client-side crash handling.
            import sys
            sys.exit(1)
        try:
            if dispatch_method is not None:
                response = dispatch_method(method, params)
            else:
                response = self._dispatch(method, params)

            # With either Unicode or normal strings, we can only transmit
            # \t, \n, \r, \u0020-\ud7ff, \ue000-\ufffd, and \u10000-\u10ffff
            # in an XML document.  xmlrpclib does not escape these values
            # properly, and then breaks when it comes to parse the document.
            # To hack around this problem, we use repr here and exec above
            # to transmit the string using Python encoding.
            # Thanks to David Mertz <mertz@gnosis.cx> for the trick (buried
            # in xml_pickle.py).
            if (isinstance(response, types.StringType) or
                isinstance(response, unicode)):
                response = repr(response)[1:-1]

            response = (response,)
            response = xmlrpclib.dumps(response,
                                       methodresponse=1,
                                       allow_none=1)
        except xmlrpclib.Fault, fault:
            response = xmlrpclib.dumps(fault)
        except Exception, exn:
            import xen.xend.XendClient
            log.exception(exn)
            response = xmlrpclib.dumps(
                xmlrpclib.Fault(xen.xend.XendClient.ERROR_INTERNAL, str(exn)))

        return response

# This is a XML-RPC server that sits on a Unix domain socket.
# It implements proper support for allow_reuse_address by
# unlink()'ing an existing socket.

class UnixXMLRPCRequestHandler(XMLRPCRequestHandler):
    def address_string(self):
        try:
            return XMLRPCRequestHandler.address_string(self)
        except ValueError, e:
            return self.client_address[:2]

class UnixXMLRPCServer(TCPXMLRPCServer):
    address_family = socket.AF_UNIX

    def __init__(self, addr, logRequests = 1):
        parent = os.path.dirname(addr)
        if os.path.exists(parent):
            os.chown(parent, os.geteuid(), os.getegid())
            os.chmod(parent, stat.S_IRWXU)
            if self.allow_reuse_address and os.path.exists(addr):
                os.unlink(addr)
        else:
            os.makedirs(parent, stat.S_IRWXU)
        TCPXMLRPCServer.__init__(self, addr, UnixXMLRPCRequestHandler,
                                 logRequests)
