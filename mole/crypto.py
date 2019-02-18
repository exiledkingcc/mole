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
    prefix_len = 4

    def __init__(self, key, nonce):
        key = hashlib.sha512(key.encode("utf-8")).digest()
        self._key = key[:LibSodium.xchacha20poly1305_ietf_keybytes]
        self._nonce = nonce.encode("utf-8")

    def encrypt(self, data: bytes):
        nonce = LibSodium.randombytes(4)
        nonce2 = hashlib.sha512(self._nonce + nonce).digest()[:LibSodium.xchacha20poly1305_ietf_npubbytes]
        e = LibSodium.xchacha20poly1305_ietf_encrypt(data, nonce2, self._key)
        e = nonce + e
        el = len(e).to_bytes(self.prefix_len, "little")
        return el + e

    def decrypt(self, data: bytes):
        nonce = data[:4]
        nonce2 = hashlib.sha512(self._nonce + nonce).digest()[:LibSodium.xchacha20poly1305_ietf_npubbytes]
        ciphertext = data[4:]
        m = LibSodium.xchacha20poly1305_ietf_decrypt(ciphertext, nonce2, self._key)
        return m
