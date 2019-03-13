# coding: utf-8

import argparse
import asyncio
import enum
import logging
import socket
import sys

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


def host_name(addr: bytes, atype):
    if atype == Socks5IpTYpe.IPV4.value:
        return utils.host_v4(atype)
    elif atype == Socks5IpTYpe.IPV6.value:
        return utils.host_v6(addr)
    elif atype == Socks5IpTYpe.Domain.value:
        return addr[1:].decode("utf-8")
    return None


class Socks5Client:
    def __init__(self, port):
        self._port = port

        self._loop = asyncio.get_event_loop()

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setblocking(False)
        self._socket.bind(("0.0.0.0", self._port))
        self._socket.listen(100)
        log.info("listening at 0.0.0.0:%s", self._port)

    def __del__(self):
        self._socket.close()

    def start(self):
        log.info("start...")
        try:
            self._loop.run_until_complete(self.serve())
        except KeyboardInterrupt:
            self._socket.close()

    async def serve(self):
        while True:
            sk, addr = await self._loop.sock_accept(self._socket)
            log.info("<== %s", addr)
            sk.setblocking(False)
            self._loop.create_task(self.handle(sk))

    async def handle(self, sk: socket.socket):
        if not await self._handle_ver(sk):
            return
        rr = await self._handle_cmd(sk)
        if not rr:
            return
        con_data, target = rr

        sk2 = await self._handle_connect(target)
        if not sk2:
            log.error("connecting %s:%s", target[0], target[1])
            await self._loop.sock_sendall(sk, b"\x05\x01\x00" + con_data)
            sk.close()
            return

        await self._loop.sock_sendall(sk, b"\x05\x00\x00" + con_data)
        log.info("connected with %s:%s", target[0], target[1])

        N = 4096
        tx_data = bytearray()
        rx_data = bytearray()
        while True:
            try:
                tx = sk.recv(N, socket.MSG_DONTWAIT)
                if tx:
                    tx_data.extend(tx)
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except ConnectionResetError:
                log.warning("ConnectionResetError sk.recv %s:%s", target[0], target[1])
                break
            except BrokenPipeError:
                log.warning("BrokenPipeError sk.recv %s:%s", target[0], target[1])
                break

            if tx_data:
                sent = sk2.send(tx_data, socket.MSG_DONTWAIT)
                del tx_data[:sent]

            try:
                rx = sk2.recv(N, socket.MSG_DONTWAIT)
                if rx:
                    rx_data.extend(rx)
            except BlockingIOError:
                await asyncio.sleep(0.1)
            except ConnectionResetError:
                log.warning("ConnectionResetError sk2.recv %s:%s", target[0], target[1])
                break
            except BrokenPipeError:
                log.warning("BrokenPipeError sk2.recv %s:%s", target[0], target[1])
                break

            if rx_data:
                try:
                    sent = sk.send(rx_data, socket.MSG_DONTWAIT)
                    del rx_data[:sent]
                except ConnectionResetError:
                    log.warning("ConnectionResetError sk.send %s:%s", target[0], target[1])
                    break
                except BrokenPipeError:
                    log.warning("BrokenPipeError sk.send %s:%s", target[0], target[1])
                    break

            await asyncio.sleep(0)

        log.info("connect done with %s:%s", target[0], target[1])
        sk.close()
        sk2.close()

    async def _handle_ver(self, sk: socket.socket):
        data = await self._loop.sock_recv(sk, 1024)
        while not data:
            await asyncio.sleep(0)
            data = await self._loop.sock_recv(sk, 1024)

        if data[0] != 5:
            log.warning("unsupported version: %s", data[0])
            await self._loop.sock_sendall(sk, b"\x05\x00")
            sk.close()
            return False

        await self._loop.sock_sendall(sk, b"\x05\x00")
        return True

    async def _handle_cmd(self, sk: socket.socket):
        data = await self._loop.sock_recv(sk, 2048)
        while not data:
            await asyncio.sleep(0)
            data = await self._loop.sock_recv(sk, 1024)

        cmd = data[1]
        con_data = data[3:]
        if cmd != Socks5Cmd.Connect.value:
            log.error("unsupported cmd: %d", cmd)
            await self._loop.sock_sendall(sk, b"\x05\x01\x00" + con_data)
            sk.close()
            return

        atype = data[3]
        host = host_name(data[4:-2], atype)
        port = utils.port_b2i(data[-2:])
        target = (host, port)
        return con_data, target

    async def _handle_connect(self, target):
        log.info("connect to %s:%s", target[0], target[1])
        try:
            info = await self._loop.getaddrinfo(target[0], target[1])
        except Exception as e:
            log.error("getaddrinfo %s:%s", target[0], target[1], exc_info=e)
            return
        info = info[0]
        sk2 = socket.socket(info[0], info[1], info[2])
        sk2.setblocking(False)
        try:
            await self._loop.sock_connect(sk2, info[-1])
        except Exception as e:
            log.error("sock_connect %s:%s", target[0], target[1], exc_info=e)
            sk2.close()
            return
        return sk2


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

    Socks5Client(args.port).start()


if __name__ == '__main__':
    sys.exit(main())
