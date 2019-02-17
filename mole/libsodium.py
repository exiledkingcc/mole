# coding=utf-8

import ctypes
import ctypes.util

_lib = ctypes.util.find_library("sodium")
if not _lib:
    raise ValueError("No libsodium available")

_LIB = ctypes.cdll.LoadLibrary(_lib)


def _ok(code):
    if code != 0:
        raise ValueError("call libsodium error with code: {}".format(code))


class LibSodium:
    _ver = None
    xchacha20poly1305_ietf_keybytes = _LIB.crypto_aead_xchacha20poly1305_ietf_keybytes()
    xchacha20poly1305_ietf_nsecbytes = _LIB.crypto_aead_xchacha20poly1305_ietf_nsecbytes()
    xchacha20poly1305_ietf_npubbytes = _LIB.crypto_aead_xchacha20poly1305_ietf_npubbytes()
    xchacha20poly1305_ietf_abytes = _LIB.crypto_aead_xchacha20poly1305_ietf_abytes()

    @staticmethod
    def version():
        if not LibSodium._ver:
            _LIB.sodium_version_string.restype = ctypes.c_char_p
            LibSodium._ver = _LIB.sodium_version_string()
        return LibSodium._ver

    @staticmethod
    def randombytes(xlen):
        buf = ctypes.create_string_buffer(xlen)
        buf_len = ctypes.c_ulonglong(xlen)
        _LIB.randombytes(buf, buf_len)
        return buf.raw

    @staticmethod
    def xchacha20poly1305_ietf_encrypt(message, nonce, key, ad=None):
        if len(nonce) != _LIB.crypto_aead_xchacha20poly1305_ietf_npubbytes():
            raise ValueError("nonce length error")
        if len(key) != _LIB.crypto_aead_xchacha20poly1305_ietf_keybytes():
            raise ValueError("key length error")

        msg_len = ctypes.c_ulonglong(len(message))
        ad_len = ctypes.c_ulonglong(len(ad) if ad else 0)
        c = ctypes.create_string_buffer(msg_len.value + _LIB.crypto_aead_xchacha20poly1305_ietf_abytes())
        c_len = ctypes.c_ulonglong(0)

        _ok(_LIB.crypto_aead_xchacha20poly1305_ietf_encrypt(
            c, ctypes.byref(c_len), message, msg_len, ad, ad_len, None, nonce, key))

        return c.raw

    @staticmethod
    def xchacha20poly1305_ietf_decrypt(ciphertext, nonce, key, ad=None):
        if len(nonce) != _LIB.crypto_aead_xchacha20poly1305_ietf_npubbytes():
            raise ValueError("nonce length error")
        if len(key) != _LIB.crypto_aead_xchacha20poly1305_ietf_keybytes():
            raise ValueError("key length error")

        c_len = ctypes.c_ulonglong(len(ciphertext))
        ad_len = ctypes.c_ulonglong(len(ad) if ad else 0)
        m = ctypes.create_string_buffer(len(ciphertext) - _LIB.crypto_aead_xchacha20poly1305_ietf_abytes())
        mgs_len = ctypes.c_ulonglong(0)

        _ok(_LIB.crypto_aead_xchacha20poly1305_ietf_decrypt(
            m, ctypes.byref(mgs_len), None, ciphertext, c_len, ad, ad_len, nonce, key))
        return m.raw
