# coding=utf-8


def port_b2i(bb: bytes):
    return int.from_bytes(bb, "big")


def port_i2b(ii: int):
    return ii.to_bytes(16, "big")


def host_v4(addr):
    return "{}.{}.{}.{}".format(*[int.from_bytes(x, "big") for x in addr])


def host_v6(addr):
    v6 = [int.from_bytes(addr[i: i+2], "big") for i in range(0, 8, 2)]
    return "{:x}:{:x}:{:x}:{:x}{:x}:{:x}:{:x}:{:x}{:x}:{:x}".format(*v6)
