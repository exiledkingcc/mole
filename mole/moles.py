# coding: utf-8

import asyncio
import logging
import socket

from mole import crypto
from mole import utils
from mole.libsodium import LibSodium
from mole.socks5 import Socks5Cmd, host_name

log = logging.getLogger(__name__)


class MoleClient:
    def __init__(self, port, remote, _crypto):
        self._port = port
        self._crypto = _crypto  # type: crypto.Crypto

        self._loop = asyncio.get_event_loop()
        self._remote = None
        asyncio.ensure_future(self._get_remote_info(remote))

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.setblocking(False)
        self._socket.bind(("0.0.0.0", self._port))
        self._socket.listen(100)
        log.info("listening at 0.0.0.0:%s", self._port)

    def __del__(self):
        self._socket.close()

    async def _get_remote_info(self, remote):
        info = await self._loop.getaddrinfo(remote[0], remote[1])
        self._remote = info[0]

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

        log.info("connect to %s:%s", target[0], target[1])
        sk2 = socket.socket(self._remote[0], self._remote[1], self._remote[2])
        try:
            sk2, cx = await self._handle_connect(sk2, con_data)
        except Exception as e:
            log.error("", exc_info=e)
            cx = None

        if not cx:
            log.error("connecting %s:%s", target[0], target[1])
            await self._loop.sock_sendall(sk, b"\x05\x01\x00" + con_data)
            sk.close()
            sk2.close()
            return

        await self._loop.sock_sendall(sk, b"\x05\x00\x00" + con_data)
        log.info("connected with %s:%s", target[0], target[1])

        N = 4096
        tx_data = bytearray()
        rx_data = bytearray()
        dx_data = bytearray()
        while True:
            try:
                tx = sk.recv(N, socket.MSG_DONTWAIT)
                if tx:
                    tx = cx.encrypt(tx)
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
                dc, dd = crypto.decrypt(cx, rx_data)
                if dc > 0:
                    del rx_data[:dc]
                    dx_data.extend(dd)

            if dx_data:
                try:
                    sent = sk.send(dx_data, socket.MSG_DONTWAIT)
                    del dx_data[:sent]
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

    async def _handle_connect(self, sk2, con_data):
        log.info("connect to remote")
        sk2.setblocking(False)
        await self._loop.sock_connect(sk2, self._remote[-1])
        data = self._crypto.encrypt(con_data)
        await self._loop.sock_sendall(sk2, data)
        rr = await self._loop.sock_recv(sk2, 1024)
        rr = self._crypto.decrypt(rr[self._crypto.prefix_len:])
        key = rr[2:6]
        nonce = rr[6: 10]
        return sk2, crypto.MoleCrypto(key, nonce)


class MoleServer:
    def __init__(self, port,  _crypto):
        self._port = port
        self._crypto = _crypto  # type: crypto.Crypto

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
        # gen session key and nonce
        key = LibSodium.randombytes(4)
        nonce = LibSodium.randombytes(4)

        sk2, target = await self._handle_connect(sk)
        if not sk2:
            log.error("connecting %s:%s", target[0], target[1])
            data = self._crypto.encrypt(b"\x01\x01" + key + nonce)
            await self._loop.sock_sendall(sk, data)
            sk.close()
            return

        log.info("connected with %s:%s", target[0], target[1])
        data = self._crypto.encrypt(b"\x00\x00" + key + nonce)
        await self._loop.sock_sendall(sk, data)

        cx = crypto.MoleCrypto(key, nonce)
        N = 8192
        tx_data = bytearray()
        rx_data = bytearray()
        dx_data = bytearray()
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
                dc, dd = crypto.decrypt(cx, tx_data)
                if dc > 0:
                    del tx_data[:dc]
                    dx_data.extend(dd)

            if dx_data:
                sent = sk2.send(dx_data, socket.MSG_DONTWAIT)
                del dx_data[:sent]

            try:
                rx = sk2.recv(N, socket.MSG_DONTWAIT)
                if rx:
                    rx = cx.encrypt(rx)
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
        data = await self._loop.sock_recv(sk, 256)
        if data[0] != 5:
            log.warning("unsupported version: %s", data[0])
            await self._loop.sock_sendall(sk, b"\x05\x00")
            sk.close()
            return False

        await self._loop.sock_sendall(sk, b"\x05\x00")
        return True

    async def _handle_cmd(self, sk: socket.socket):
        data = await self._loop.sock_recv(sk, 2048)
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

    async def _handle_connect(self, sk: socket.socket):
        data = await self._loop.sock_recv(sk, 2048)
        data = self._crypto.decrypt(data[self._crypto.prefix_len:])

        atype = data[0]
        host = host_name(data[1:-2], atype)
        port = utils.port_b2i(data[-2:])
        target = (host, port)
        log.info("connect to %s:%s", host, port)
        try:
            info = await self._loop.getaddrinfo(target[0], target[1])
        except Exception as e:
            log.error("", exc_info=e)
            return None, target

        info = info[0]
        sk2 = socket.socket(info[0], info[1], info[2])
        sk2.setblocking(False)
        try:
            await self._loop.sock_connect(sk2, info[-1])
            return sk2, target
        except Exception as e:
            log.error("", exc_info=e)
            sk2.close()
            return None, target
