# coding: utf-8

import hashlib

from mole.libsodium import LibSodium


class Crypto:
    prefix_len = 0

    def encrypt(self, data: bytes):
        raise NotImplemented

    def decrypt(self, data: bytes):
        raise NotImplemented


class PlainCrypto(Crypto):
    def encrypt(self, data: bytes):
        return data

    def decrypt(self, data: bytes):
        return data


class MoleCrypto(Crypto):
    prefix_len = 2
    keybytes = LibSodium.xchacha20poly1305_ietf_keybytes
    npubbytes = LibSodium.xchacha20poly1305_ietf_npubbytes

    def __init__(self, key, nonce):
        if isinstance(key, str):
            key = key.encode("utf-8")
        if isinstance(nonce, str):
            nonce = nonce.encode("utf-8")
        key = hashlib.sha512(key).digest()
        self._key = key[:self.keybytes]
        self._nonce = nonce

    def encrypt(self, data: bytearray):
        nonce = LibSodium.randombytes(2)
        nonce2 = hashlib.sha512(self._nonce + nonce).digest()[:self.npubbytes]
        e = LibSodium.xchacha20poly1305_ietf_encrypt(bytes(data), nonce2, self._key)
        el = (len(e) + 2).to_bytes(self.prefix_len, "little")
        return el + nonce + e

    def decrypt(self, data: bytearray):
        nonce = data[:2]
        nonce2 = hashlib.sha512(self._nonce + nonce).digest()[:self.npubbytes]
        cipher = bytes(data[2:])
        m = LibSodium.xchacha20poly1305_ietf_decrypt(cipher, nonce2, self._key)
        return m


def decrypt(cx: Crypto, data: bytearray):
    pl = cx.prefix_len
    dlen = len(data)
    if dlen <= pl:
        return 0, b""
    xlen = int.from_bytes(data[:pl], "little")
    if dlen < pl + xlen:
        return 0, b""

    dd = data[pl: pl + xlen]
    dd = cx.decrypt(dd)
    return pl + xlen, dd
