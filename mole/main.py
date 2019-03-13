#!/usr/bin/python3
# coding: utf-8

import argparse
import logging
import sys

from mole import cclog
from mole import crypto
from mole.moles import MoleClient, MoleServer


log = logging.getLogger(__name__)


def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--dev", help="dev mode", action="store_true")
    parser.add_argument("-p", "--port", help="listening port", type=int, default=8888)
    parser.add_argument("-r", "--remote", help="remote server endpoint", default="localhost:9999")
    parser.add_argument("mode", help="run mode", choices=["client", "server", "proxy"])
    args = parser.parse_args(args=args)

    cclog.init(level=logging.DEBUG if args.dev else logging.INFO)

    _crypto = crypto.MoleCrypto("hello", "world")

    if args.mode == "client":
        host, port = args.remote.split(":")
        remote = (host, int(port))
        MoleClient(args.port, remote, _crypto).start()
    elif args.mode == "server":
        MoleServer(args.port, _crypto).start()
    else:
        log.warning("TODO %s", args.mode)


if __name__ == '__main__':
    sys.exit(main())
