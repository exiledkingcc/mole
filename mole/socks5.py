# coding: utf-8

import argparse
import asyncio
import enum
import logging
import socket
import sys
import traceback

from mole import cclog
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


class Socks5Protocol(asyncio.Protocol):
    def __init__(self, loop, dev=False):
        self._loop = loop  # type: asyncio.AbstractEventLoop
        self._dev = dev

        self._socket = None  # type: socket.socket
        self._transport = None
        self._peer_name = None
        self._target_name = None
        self._con_data = None  # type: bytes
        self._state = None  # type: Socks5State
        self._tx_data = b""

    def connection_made(self, transport):
        self._transport = transport
        self._peer_name = self._transport.get_extra_info('peername')
        log.info("<<== %s", self._peer_name)
        self._state = Socks5State.Ver

    def connection_lost(self, exc):
        log.info("%s ==>", self._peer_name)

    def data_received(self, data: bytes):
        if self._state == Socks5State.Ver:
            asyncio.ensure_future(self._handle_ver(data))
        elif self._state == Socks5State.Auth:
            asyncio.ensure_future(self._handle_connect(data))
        elif self._state == Socks5State.Stream:
            self._tx_data += data

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
        if atype == Socks5IpTYpe.IPV4.value or atype == Socks5IpTYpe.IPV6.value:
            host = addr.decode("ascii")
        elif atype == Socks5IpTYpe.Domain.value:
            host = addr[1:].decode("utf-8")
        else:
            log.error("unsupported atype: %d", atype)
            self._transport.write(b"\x05\x01")
            self._state = Socks5State.Done
            return

        port = utils.port_b2i(port)
        self._target_name = (host, port)
        # noinspection PyBroadException
        try:
            await self._connect_target(host, port)
        except Exception:
            log.error("connect_target %s", self._target_name)
            self._transport.write(b"\x05\x01")
            self._state = Socks5State
        return True

    async def _connect_target(self, host, port):
        log.info("connect %s:%d", host, port)
        info = await self._loop.getaddrinfo(host, port)
        info = info[0]
        self._socket = socket.socket(info[0], info[1], info[2])
        self._socket.setblocking(False)
        await self._loop.sock_connect(self._socket, info[-1])
        self._loop.add_reader(self._socket, self._recv)
        self._loop.add_writer(self._socket, self._send)
        self._transport.write(b"\x05\x00" + self._con_data[2:])
        self._state = Socks5State.Stream

    def _send(self):
        if not self._tx_data:
            return
        if not self._socket or self._socket.fileno() < 0:
            return
        try:
            sent = self._socket.send(self._tx_data, socket.SOCK_NONBLOCK)
            self._tx_data = self._tx_data[sent:]
        except BrokenPipeError:
            log.error("BrokenPipeError send %s", self._target_name)
            self._socket.close()
            self._state = Socks5State.Done
        except Exception as e:
            log.error("", exc_info=e)

    def _recv(self):
        if not self._socket or self._socket.fileno() < 0:
            return
        try:
            data = self._socket.recv(2048, socket.SOCK_NONBLOCK)
            if data:
                self._transport.write(data)
        except BrokenPipeError:
            log.error("BrokenPipeError recv %s", self._target_name)
            self._socket.close()
            self._state = Socks5State.Done
        except Exception as e:
            log.error("", exc_info=e)


def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dev", help="dev mode", action="store_true")
    parser.add_argument("-p", "--port", help="listening port", default=8888)
    args = parser.parse_args(args=args)

    loop = asyncio.get_event_loop()
    if args.dev:
        loop.set_debug(True)
        cclog.init(level=logging.DEBUG)
    else:
        cclog.init(level=logging.INFO)

    log.info("listening at 0.0.0.0:%s", args.port)
    coro = loop.create_server(lambda: Socks5Protocol(loop, dev=args.dev), "0.0.0.0", args.port)
    server = loop.run_until_complete(coro)
    # noinspection PyBroadException
    try:
        loop.run_forever()
    except Exception:
        traceback.print_exc()
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())


if __name__ == '__main__':
    sys.exit(main())
