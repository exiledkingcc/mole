#!/usr/bin/python3
# coding: utf-8

import argparse
import asyncio
import logging
import socket
import sys
import traceback

from mole import crypto
from mole.moles import MoleClientProtocol, MoleServerProtocol


log = logging.getLogger(__name__)


def client(layer,  listen_port, remote, dev=False):
    log.info("run in client mode...")
    host, port = remote.split(":")
    remote = socket.getaddrinfo(host, int(port))
    remote = remote[0]

    loop = asyncio.get_event_loop()

    log.info("listening at 0.0.0.0:%s", listen_port)
    coro = loop.create_server(lambda: MoleClientProtocol(loop, remote, layer, dev=dev), "0.0.0.0", listen_port)

    run(loop, coro)


def server(layer, listen_port, dev=False):
    log.info("run in server mode...")

    loop = asyncio.get_event_loop()

    log.info("listening at 0.0.0.0:%s", listen_port)
    coro = loop.create_server(lambda: MoleServerProtocol(loop, layer, dev=dev), "0.0.0.0", listen_port)

    run(loop, coro)


def run(loop, coro):
    server = loop.run_until_complete(coro)
    # noinspection PyBroadException
    try:
        loop.run_forever()
    except Exception:
        traceback.print_exc()
    finally:
        server.close()
        loop.run_until_complete(server.wait_closed())


def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dev", help="dev mode", action="store_true")
    parser.add_argument("-p", "--port", help="listening port", default=8888)
    parser.add_argument("-r", "--remote", help="remote server endpoint", default="localhost:9999")
    parser.add_argument("mode", help="run mode", choices=["client", "server", "proxy"])
    args = parser.parse_args(args=args)

    layer = crypto.MoleCrypto("hello", "world")

    if args.mode == "client":
        return client(layer, args.port, args.remote, args.dev)
    elif args.mode == "server":
        return server(layer, args.port, args.dev)
    else:
        log.error("unsupported mode %s", args.mode)


if __name__ == '__main__':
    try:
        import cclog
        cclog.init()
    except ImportError:
        logging.basicConfig(
            stream=sys.stderr,
            level=logging.DEBUG,
            format="%(asctime)s [%(levelname)s] [%(name)s] [%(threadName)s] [%(funcName)s]: %(message)s"
        )
    sys.exit(main())
