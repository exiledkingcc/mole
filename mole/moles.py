# coding: utf-8

import asyncio
import enum
import logging
import socket

from mole import crypto
from mole import utils

log = logging.getLogger(__name__)


class Socks5Cmd(enum.IntEnum):
    Connect = 1
    Bind = 2
    Udp = 3


class Socks5IpTYpe(enum.IntEnum):
    IPV4 = 1
    Domain = 3
    IPV6 = 4


class Socks5State(enum.IntEnum):
    Ver = 0
    Auth = 1
    Connect = 2
    Stream = 3
    Done = 4


class MoleClientProtocol(asyncio.Protocol):
    def __init__(self, loop, remote, layer, dev=False):
        self._loop = loop  # type: asyncio.AbstractEventLoop
        self._remote = remote[-1]
        self._layer = layer  # type: crypto.Crypto
        self._dev = dev

        self._socket = socket.socket(remote[0], remote[1], remote[2])
        self._socket.setblocking(False)
        self._transport = None
        self._peer = None
        self._target = None
        self._con_data = None  # type: bytes
        self._state = None  # type: Socks5State
        self._tx_data = b""
        self._rx_data = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = self._transport.get_extra_info('peername')
        log.info("<<== %s", self._peer)
        self._state = Socks5State.Ver

        asyncio.ensure_future(self._connect_remote())

    def connection_lost(self, exc):
        log.info("%s ==>", self._peer)
        # noinspection PyBroadException
        try:
            self._loop.remove_reader(self._socket)
            self._loop.remove_writer(self._socket)
            self._socket.close()
        except Exception:
            pass

    def data_received(self, data: bytes):
        if self._state == Socks5State.Ver:
            asyncio.ensure_future(self._handle_ver(data))
        elif self._state == Socks5State.Auth:
            asyncio.ensure_future(self._handle_connect(data))
        elif self._state == Socks5State.Stream:
            self._tx_data += self._layer.encrypt(data)
        elif self._state == Socks5State.Done:
            self._transport.close()

    async def _handle_ver(self, data: bytes):
        if data[0] == 5 or data[0] == 4:
            self._transport.write(b"\x05\x00")
            self._state = Socks5State.Auth
            return True
        else:
            log.warning("Unsupported version %s", data[0])
            self._transport.write(b"\x05\x01")
            self._state = Socks5State.Done

    async def _handle_connect(self, data: bytes):
        cmd = data[1]
        if cmd != Socks5Cmd.Connect.value:
            log.error("unsupported cmd: %d", cmd)
            self._transport.write(b"\x05\x01")
            self._state = Socks5State.Done
            return

        atype = data[3]
        addr = data[4:-2]
        port = data[-2:]
        self._con_data = data
        if atype not in (Socks5IpTYpe.IPV4.value, Socks5IpTYpe.IPV6.value, Socks5IpTYpe.Domain.value):
            log.error("unsupported atype: %d", atype)
            self._transport.write(b"\x05\x01")
            self._state = Socks5State.Done
            return

        data = data[3:4] + port + addr
        self._target = (addr, port)
        self._state = Socks5State.Connect
        self._tx_data += self._layer.encrypt(data)
        return True

    async def _connect_remote(self):
        await self._loop.sock_connect(self._socket, self._remote)
        self._loop.add_reader(self._socket, self._recv)
        self._loop.add_writer(self._socket, self._send)

    def _send(self):
        if not self._tx_data:
            return
        if not self._socket or self._socket.fileno() < 0:
            return
        try:
            sent = self._socket.send(self._tx_data, socket.SOCK_NONBLOCK)
            self._tx_data = self._tx_data[sent:]
        except BrokenPipeError:
            log.error("BrokenPipeError send %s", self._remote)
            self._socket.close()
            self._state = Socks5State.Done
        except Exception as e:
            log.error("", exc_info=e)

    def _recv(self):
        if not self._socket or self._socket.fileno() < 0:
            return
        try:
            data = self._socket.recv(2048, socket.SOCK_NONBLOCK)
            if not data:
                return
            self._rx_data += data
            rx_len = len(self._rx_data)
            pl = self._layer.prefix_len
            if rx_len < pl:
                return
            xlen = int.from_bytes(self._rx_data[:pl], "little")
            if rx_len < pl + xlen:
                return
            rx_data = self._rx_data[pl:pl + xlen]
            self._rx_data = self._rx_data[pl + xlen:]

            rx_data = self._layer.decrypt(rx_data)
            if self._state == Socks5State.Connect:
                if rx_data[0] == 0:
                    log.info("connect target %s", self._target)
                    self._transport.write(b"\x05\x00" + self._con_data[2:])
                    self._state = Socks5State.Stream
                else:
                    log.error("connect target %s", self._target)
                    self._transport.write(b"\x05\x01" + self._con_data[2:])
                    self._state = Socks5State.Done
            elif self._state == Socks5State.Stream:
                self._transport.write(rx_data)
            else:
                log.error("error state %s", self._state)
        except BrokenPipeError:
            log.error("BrokenPipeError recv %s", self._remote)
            self._socket.close()
            self._state = Socks5State.Done
        except Exception as e:
            log.error("", exc_info=e)


class MoleServerProtocol(asyncio.Protocol):
    def __init__(self, loop, layer, dev=False):
        self._loop = loop  # type: asyncio.AbstractEventLoop
        self._layer = layer  # type: crypto.Crypto
        self._dev = dev

        self._socket = None  # type: socket.socket
        self._transport = None
        self._peer = None
        self._target = None
        self._con_data = None  # type: bytes
        self._state = None  # type: Socks5State
        self._tx_data = b""
        self._rx_data = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer = self._transport.get_extra_info('peername')
        log.info("<<== %s", self._peer)
        self._state = Socks5State.Connect

    def connection_lost(self, exc):
        log.info("%s ==>", self._peer)
        # noinspection PyBroadException
        try:
            self._loop.remove_reader(self._socket)
            # self._loop.remove_writer(self._socket)
            self._socket.close()
        except Exception:
            pass

    def data_received(self, data: bytes):
        if self._state != Socks5State.Connect and self._state != Socks5State.Stream:
            self._transport.close()
            return

        self._rx_data += data
        rx_len = len(self._rx_data)
        pl = self._layer.prefix_len
        if rx_len < pl:
            return
        xlen = int.from_bytes(self._rx_data[:pl], "little")
        if rx_len < pl + xlen:
            return
        rx_data = self._rx_data[pl:pl + xlen]
        self._rx_data = self._rx_data[pl + xlen:]

        try:
            rx_data = self._layer.decrypt(rx_data)
        except ValueError:
            log.error("decrypt error!")
            self._state = Socks5State.Done
            self._transport.close()

        asyncio.ensure_future(self._handle_data(rx_data))

    async def _handle_data(self, data: bytes):
        if self._state == Socks5State.Connect:
            atype = data[0]
            port = data[1:3]
            addr = data[3:]
            if atype == Socks5IpTYpe.IPV4.value or atype == Socks5IpTYpe.IPV6.value:
                host = addr.decode("ascii")
            else:
                host = addr[1:].decode("utf-8")
            port = utils.port_b2i(port)
            self._target = (host, port)
            # noinspection PyBroadException
            try:
                log.info("connect to %s:%d", host, port)
                await self._connect_target(host, port)
                log.info("connected %s:%d ok", host, port)
                self._state = Socks5State.Stream
            except Exception:
                log.error("connect_target %s", self._target)
                reply = b"\x01\x00\x00\x00"
                reply = self._layer.encrypt(reply)
                self._transport.write(reply)
                self._state = Socks5State.Done
        else:
            self._tx_data += data
            try:
                sent = self._socket.send(self._tx_data, socket.SOCK_NONBLOCK)
                self._tx_data = self._tx_data[sent:]
            except BrokenPipeError:
                log.error("BrokenPipeError send %s", self._target)
                self._socket.close()
                self._state = Socks5State.Done
            except Exception as e:
                log.error("", exc_info=e)

        return True

    async def _connect_target(self, host, port):
        info = await self._loop.getaddrinfo(host, port)
        info = info[0]
        self._socket = socket.socket(info[0], info[1], info[2])
        self._socket.setblocking(False)
        self._socket.settimeout(5)
        await self._loop.sock_connect(self._socket, info[-1])
        self._loop.add_reader(self._socket, self._recv)
        reply = b"\x00\x00\x00\x00"
        reply = self._layer.encrypt(reply)
        self._transport.write(reply)

    def _recv(self):
        if not self._socket or self._socket.fileno() < 0:
            return
        try:
            data = self._socket.recv(2048, socket.SOCK_NONBLOCK)
            if data:
                data = self._layer.encrypt(data)
                self._transport.write(data)
        except BrokenPipeError:
            log.error("BrokenPipeError recv %s", self._target)
            self._socket.close()
            self._state = Socks5State.Done
        except Exception as e:
            log.error("", exc_info=e)
