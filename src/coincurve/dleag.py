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


def _generator_ptr(name):
    # copy the const generator into a writable allocation, its address cannot be taken directly.
    gp = ffi.new('secp256k1_generator *')
    gp[0] = getattr(lib, name)
    return gp


def dleag_prove_gen(private_key, gen_e_a, gen_e_b, nonce_bytes=None, context=GLOBAL_CONTEXT):
    # parameterized on ed25519 generators gen_e_a and gen_e_b, secp256k1 side uses G and H.
    if len(gen_e_a) != 32 or len(gen_e_b) != 32:
        raise ValueError('Invalid ed25519 generator length')

    gen_e_a = ffi.from_buffer(gen_e_a)
    gen_e_b = ffi.from_buffer(gen_e_b)

    proof_length = dleag_proof_len()
    proof_output = ffi.new('unsigned char[{}]'.format(proof_length))

    proof_length_p = ffi.new('size_t *')
    proof_length_p[0] = proof_length

    if nonce_bytes is None:
        nonce_bytes = get_nonce()
    elif len(nonce_bytes) != 32:
        raise ValueError('Invalid nonce length')

    rv = lib.secp256k1_dleag_prove(
        context.ctx,
        proof_output,
        proof_length_p,
        private_key.secret,
        252,
        nonce_bytes,
        _generator_ptr('secp256k1_generator_const_g'),
        _generator_ptr('secp256k1_generator_const_h'),
        gen_e_a,
        gen_e_b,
    )

    if rv != 1:
        raise ValueError('secp256k1_dleag_prove failed')

    return bytes(ffi.buffer(proof_output, proof_length_p[0]))


def dleag_verify_gen(proof, gen_e_a, gen_e_b, context=GLOBAL_CONTEXT):
    if len(gen_e_a) != 32 or len(gen_e_b) != 32:
        raise ValueError('Invalid ed25519 generator length')

    gen_e_a = ffi.from_buffer(gen_e_a)
    gen_e_b = ffi.from_buffer(gen_e_b)

    proof_bytes = ffi.from_buffer(proof)
    proof_length = len(proof)

    rv = lib.secp256k1_dleag_verify(
        context.ctx,
        proof_bytes,
        proof_length,
        _generator_ptr('secp256k1_generator_const_g'),
        _generator_ptr('secp256k1_generator_const_h'),
        gen_e_a,
        gen_e_b,
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
