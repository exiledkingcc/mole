# coding=utf-8


def port_b2i(bb: bytes):
    return int.from_bytes(bb, "big")


def port_i2b(ii: int):
    return ii.to_bytes(16, "big")

