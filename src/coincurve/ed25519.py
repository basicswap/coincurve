from coincurve.utils import int_to_bytes_padded
from ._libsecp256k1 import ffi, lib

import secrets


GROUP_ORDER_INT = 2 ** 252 + 27742317777372353535851937790883648493


def get_valid_secret():
    return int_to_bytes_padded(9 + secrets.randbelow(GROUP_ORDER_INT - 9))


def ed25519_get_pubkey(privkey):
    pubkey_output = ffi.new('unsigned char[{}]'.format(32))
    privkey_le = privkey[::-1]
    rv = lib.crypto_scalarmult_ed25519_base_noclamp(pubkey_output, privkey_le)
    if rv != 0:
        raise ValueError('crypto_scalarmult_ed25519_base_noclamp failed')
    return bytes(ffi.buffer(pubkey_output, 32))


def ed25519_scalar_add(x, y):
    output = ffi.new('unsigned char[{}]'.format(32))
    x_le = x[::-1]
    y_le = y[::-1]
    lib.crypto_core_ed25519_scalar_add(output, x_le, y_le)
    return bytes(ffi.buffer(output, 32))[::-1]


def ed25519_add(x, y):
    output = ffi.new('unsigned char[{}]'.format(32))
    rv = lib.crypto_core_ed25519_add(output, x, y)
    if rv != 0:
        raise ValueError('crypto_core_ed25519_add failed')
    return bytes(ffi.buffer(output, 32))
