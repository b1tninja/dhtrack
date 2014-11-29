#!/usr/bin/env python3

# magnet:?xt=urn:btih:09b3a16672eddf0b812852e20df21b484ef45bdb&dn=archlinux-2014.09.03-dual.iso&tr=udp://tracker.archlinux.org:6969&tr=http://tracker.archlinux.org:6969/announce

#


from gi.repository import GLib, Gio, GObject, Gtk


MTU = 1438
PEER_FILE = 'peers.dat'

import binascii

from contextlib import closing
from torrent import Torrent
from bencode import BEncode
import struct
import os

from ipaddress import IPv4Address, IPv6Address


import socket

try:
    import signal
except ImportError:
    signal = None

from gi.repository import GObject

# class KRPC(object):
# def __init__(self, decoded):
#         assert('y' in decoded)
#         assert(decoded['y'] in ['q', 'r', 'e'])
#         assert(decoded['y'] in decoded)
#         self.y = decoded['y']
#         if 't' not in decoded:
#             self.t = os.urandom(2)
#         else:
#             self.t = decoded['t']
#
# #  Code	Description
# #  201	Generic Error
# #  202	Server Error
# #  203	Protocol Error, such as a malformed packet, invalid arguments, or bad token
# #  204	Method Unknown
#
#     @classmethod
#     def parse(cls, buffer):
#         try:
#             decoded = BEncode.parse(buffer)
#         except:
#             print('Failed during parsing of bencoded data.')
#         else:
#             if decoded['y'] == b'q':
#                 # krpc_classes = {'ping': Ping,
#                 #                 'find_node': FindNode,
#                 #                 'get_peers': GetPeers,
#                 #                 'announce_peer': AnnouncePeer}
#                 # assert(decoded['q'] in krpc_classes)
#
#                 return krpc_classes[decoded['q']]
#             elif decoded['y'] == b'r':
#                 return Response(decoded)
#             elif decoded['y'] == b'e':
#                 return Error(decoded)
#             else:
#                 return cls(decoded)

def node_metric(a, b):
    assert (len(a) == 20)
    assert (len(b) == 20)
    return sum([(a[-n] ^ b[-n]) * 256 ** n for n in range(20)])

#    return abs(node_metric(a) - node_metric(b))


class DHTPeer(object):
    def __init__(self, dht_node, node_id, ip, port):
        assert(isinstance(ip, IPv4Address) or isinstance(ip, IPv6Address))

        self.queue = {}
        self.dht_node = dht_node

        self.ip = ip
        self.port = port

        self.node_id = node_id

        if node_id is None:
            #self.node_id = os.urandom(20) # TODO: something better
            self.ping()
        else:
            lstPeers.append((binascii.b2a_hex(self.node_id).decode('ASCII'), self.ip.exploded, str(self.port)))






    def write(self, data):
        if isinstance(self.ip, IPv4Address):
            self.dht_node.sock.sendto(data, (self.ip.exploded, self.port))

        if isinstance(self.ip, IPv6Address):
            self.dht_node.sock6.sendto(data, (self.ip.exploded, self.port))

    def recv(self, data):
        parsed = BEncode.parse(data)

        # Query:
        if parsed['y'] == b'q':
            assert('q' in parsed)
            if parsed['q'] == b'ping':
                self.respond(parsed['t'])
            elif parsed['q'] == b'find_node':
                pass
            elif parsed['q'] == b'get_peers':
                pass
            elif parsed['q'] == b'announce_peer':
                pass
            else:
                log("Unknown query!", parsed['q'])
        else:

            try:
                assert('t' in parsed)
                if parsed['t'] not in self.queue:
                    log("No matching transaction id for data:\n\t" + repr(parsed))
                else:
                    # Transaction found
                    q = self.queue[parsed['t']]
                    del self.queue[parsed['t']]


                    # Response
                    if parsed['y'] == b'r':

                        if q['q'] == 'ping':
                            self.node_id = parsed['r']['id']

                        if q['q'] == 'find_node':

                            assert ('r' in parsed)
                            assert ('nodes' in parsed['r'])
                            for n in range(0, len(parsed['r']['nodes']), 26):
                                node_id = parsed['r']['nodes'][n:n + 20]
                                ip = IPv4Address(parsed['r']['nodes'][n + 20:n + 24])
                                (port,) = struct.unpack('!H', parsed['r']['nodes'][n + 24:n + 26])

                                # TODO: clean up handling of node_id is None
                                if len(self.dht_node.peers) < 16 or self.node_id is None or node_metric(q['a']['target'], node_id) <= node_metric(q['a']['target'], self.node_id):
                                    if (ip.exploded, port) not in self.dht_node.peers:
                                        new_peer = self.dht_node.add_peer(node_id, ip, port)
                                        new_peer.find_node(q['a']['target'])


                            if socket.has_ipv6 and 'nodes6' in parsed['r']:
                                for n in range(0, len(parsed['r']['nodes']), 38):
                                    node_id = parsed['r']['nodes'][n:n + 20]
                                    ip = IPv6Address(parsed['r']['nodes'][n + 20:n + 36])
                                    (port,) = struct.unpack('!H', parsed['r']['nodes'][n + 36:n + 38])

                                    # TODO: clean up handling of node_id is None
                                    if len(self.dht_node.peers) < 16 or self.node_id is None or node_metric(q['a']['target'], node_id) <= node_metric(q['a']['target'], self.node_id):
                                        if (ip.exploded, port) not in self.dht_node.peers:
                                            pass
                                            # new_peer = self.dht_node.add_peer(node_id, ip, port)
                                            # new_peer.find_node(q['a']['target'])

                            self.dht_node.save_peers()

                        log("%s -> %s:\n\t%s\n\t%s" % (self, self.dht_node, q, parsed))


                    elif parsed['y'] == b'e':  # Error
                        pass

                    else:
                        raise Exception("Invalid y")

            except AssertionError:
                pass


    def respond(self, t, r={}):
        r['id'] = self.dht_node.node_id
        r['ip'] = self.ip.exploded
        krpc = ({'t': t,
                 'y': 'r',
                 'r': r})
        log("%s -> %s\n\t%s" % (self.dht_node, self, krpc))
        self.write(BEncode.encode(krpc))


    def query(self, q, a={}):
        t = os.urandom(2)
        a['id'] = self.dht_node.node_id
        krpc = ({'t': t,
                 'y': 'q',
                 'q': q,
                 'a': a})
        self.queue[t] = krpc
        log("%s -> %s\n\t%s" % (self.dht_node, self, krpc))
        self.write(BEncode.encode(krpc))

    def ping(self):
        self.query('ping')

    def find_node(self, node_id):
        # want = ['n4']
        # if socket.has_ipv6:
        #     want.append(('n6'))
        #
        # self.query('find_node', {'target': node_id,'want':want})

        self.query('find_node', {'target': node_id})

    def __repr__(self):
#        return "peer %s:%d" % (self.ip.exploded, self.port)
        return "peer %s (%s:%d)" % ('UNKNOWN' if self.node_id is None else binascii.b2a_hex(self.node_id),
                                     self.ip.exploded,
                                     self.port)


class DHTNode:
    def __repr__(self):
#        return "node %s %s:%d)" % ()
#         if socket.has_ipv6:
#             return "node %s (%s:%d. %s:%d)" % (binascii.b2a_hex(self.node_id), self.sock)
        return "node %s" % (binascii.b2a_hex(self.node_id))

    def __init__(self, node_id=os.urandom(20), addr=('',0)):
        self.peers = {}
        self.node_id = node_id

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(addr)
        # Add event handler for ipv4 socket
        GObject.io_add_watch(self.sock, GObject.IO_IN, self.datagram_received)

        if socket.has_ipv6:
            self.sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            # Because of inconsistencies between OSes, disable ipv4/6 dual stack
            if getattr(socket, 'IPV6_V6ONLY', False):
                self.sock6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, True)
            self.sock6.bind(addr)
            # Add event handler for ipv6 socket
            GObject.io_add_watch(self.sock6, GObject.IO_IN, self.datagram_received)

    def bootstrap(self):
        # Bootstrap, find "neighbors"
        for peer in dht_node.peers.values():
            peer.find_node(dht_node.node_id)



    def datagram_received(self, transport, condition):
        if transport.family == socket.AF_INET:
            pass
        if transport.family == socket.AF_INET6:
            pass

        (data, addr) = transport.recvfrom(MTU)

        if addr in self.peers:
            self.peers[addr].recv(data)
        else:
            log('Data received from unknown peer:', data, addr)
            self.add_peer(None, *addr)
            # TODO: Add peer, ping

        # Part of the Gio convention...
        return True

    def connection_refused(self, exc):
        log('Connection refused:', exc)

    def connection_lost(self, exc):
        log('stop', exc)

    def add_peer(self, node_id, ip, port):
        assert(isinstance(ip, IPv4Address) or isinstance(ip, IPv6Address))

        if (ip.exploded, port) not in self.peers:
            # TODO: Consider allowing (addr, port) to map to multiple node_id endpoints for tracking purposes
            peer = DHTPeer(self, node_id, ip, port)
            self.peers[(ip.exploded, port)] = peer
            return peer


    def save_peers(self, path=PEER_FILE):
        # TODO: fix to support ipv6
        with closing(open(path, 'wb')) as fh:
            for peer in self.peers.values():
                if peer.node_id is not None:
                    fh.write(peer.node_id +
                             peer.ip.packed +
                             struct.pack('!H', peer.port))

    def load_peers(self, path=PEER_FILE):
        with closing(open(path, 'rb')) as fh:
            while True:
                chunk = fh.read(26)
                if chunk:
                    self.add_peer(chunk[:20],
                                  IPv4Address(chunk[20:24]),
                                  struct.unpack('!H', chunk[24:26])[0])
                else:
                    break

def bootstrap(*args):
    log(dht_node)
    routers = ['router.bittorrent.com',
               'download.deluge-torrent.org',
               'ftp.osuosl.org',
               'router.utorrent.com',
               'router.bitcomet.com',
               ]

    for router in routers:
        try:
            for addrinfo in socket.getaddrinfo(router, 6881, proto=socket.SOL_UDP):
                (family, socktype, proto, cn, addr) = addrinfo
                (host, port) = addr

                if family == socket.AF_INET:
                    ip = IPv4Address(host)
                if family == socket.AF_INET6:
                    ip = IPv6Address(host)

                # TODO: ugh, this has "ip" not set yet written all over it

                new_peer = dht_node.add_peer(None, ip, port)

                # Since I can't think of a cleaner way to handle displaying nodes with unknown node_ids... this
                lstPeers.append((router, ip.exploded, str(port)))

                if new_peer:
                    new_peer.find_node(dht_node.node_id)

        except socket.gaierror:
            # name resolution error?
            pass

def log(buffer):
    # TODO: make a class to contain all this UI crap
    bufStatus.insert(bufStatus.get_end_iter(), str(buffer)+"\n")

def ui_stuff(*args):
    return True

if __name__ == '__main__':
    GObject.threads_init()

    # dht_node.load_peers()

    builder = Gtk.Builder()
    builder.add_from_file("dhtrack.glade")

    window = builder.get_object("winMain")
    bufStatus = builder.get_object("bufStatus")

    lblStatus = builder.get_object("lblStatus")

    lstPeers = builder.get_object("lstPeers")

    dht_node = DHTNode()
    lblStatus.set_text(binascii.b2a_hex(dht_node.node_id).decode('ASCII'))


    log('Loading...')

    handlers = {
        "onDeleteWindow": Gtk.main_quit,
#        "onButtonPressed": hello
    }
    builder.connect_signals(handlers)

    window.show_all()
    GLib.idle_add(ui_stuff)

    Gio.io_scheduler_push_job(bootstrap, None, GLib.PRIORITY_DEFAULT, None)
    Gtk.main()