from coincurve.context import GLOBAL_CONTEXT
from ._libsecp256k1 import ffi, lib
import secrets


def dleag_proof_len(bits=252):
    return lib.secp256k1_dleag_size(bits)


def get_nonce():
    return secrets.token_bytes(32)


def dleag_prove(private_key, nonce_bytes=None, context=GLOBAL_CONTEXT):
    proof_length = dleag_proof_len()
    proof_output = ffi.new('unsigned char[{}]'.format(proof_length))

    proof_length_p = ffi.new('size_t *')
    proof_length_p[0] = proof_length

    # nonce_bytes = ffi.from_buffer(secrets.token_bytes(32))
    if nonce_bytes is None:
        nonce_bytes = get_nonce()
    rv = lib.secp256k1_ed25519_dleag_prove(
        context.ctx,
        proof_output,
        proof_length_p,
        private_key.secret,
        252,
        nonce_bytes,
    )

    if rv != 1:
        raise ValueError('secp256k1_ed25519_dleag_prove failed')

    # TODO: How to clear memory? Add random module to secp256k1?
    # ffi.memmove(nonce_bytes, bytes([0] * 32), 32)
    return bytes(ffi.buffer(proof_output, proof_length))


def dleag_verify(proof, context=GLOBAL_CONTEXT):
    proof_bytes = ffi.from_buffer(proof)
    proof_length = len(proof)

    rv = lib.secp256k1_ed25519_dleag_verify(
        context.ctx,
        proof_bytes,
        proof_length,
    )

    return True if rv == 1 else False


def verify_secp256k1_point(pubkey_bytes, context=GLOBAL_CONTEXT):
    if len(pubkey_bytes) != 33:
        raise ValueError('Invalid pubkey length')

    rv = lib.secp256k1_dleag_verify_secp256k1_point(
        context.ctx,
        pubkey_bytes
    )

    return True if rv == 1 else False


def verify_ed25519_point(pubkey_bytes, context=GLOBAL_CONTEXT):
    if len(pubkey_bytes) != 32:
        raise ValueError('Invalid pubkey length')

    rv = lib.secp256k1_dleag_verify_ed25519_point(
        context.ctx,
        pubkey_bytes
    )

    return True if rv == 1 else False
