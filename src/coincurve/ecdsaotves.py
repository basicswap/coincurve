from coincurve.context import GLOBAL_CONTEXT
from ._libsecp256k1 import ffi, lib


def ecdsaotves_enc_sign(private_key_sign, public_key_encrypt, msg, context=GLOBAL_CONTEXT):
    ct_length = 196
    ct_output = ffi.new('unsigned char[{}]'.format(ct_length))

    if len(private_key_sign) != 32:
        raise ValueError('private_key_sign must be 32 bytes')
    if len(public_key_encrypt) != 33:
        raise ValueError('public_key_encrypt must be 33 bytes')
    if len(msg) != 32:
        raise ValueError('msg must be 32 bytes')

    rv = lib.ecdsaotves_enc_sign(
        context.ctx,
        ct_output,
        private_key_sign,
        public_key_encrypt,
        msg)

    if rv != 1:
        raise ValueError('ecdsaotves_enc_sign failed')

    return bytes(ffi.buffer(ct_output, ct_length))


def ecdsaotves_enc_verify(public_key_sign, public_key_encrypt, msg, ct, context=GLOBAL_CONTEXT):
    if len(public_key_sign) != 33:
        raise ValueError('public_key_sign must be 33 bytes')
    if len(public_key_encrypt) != 33:
        raise ValueError('public_key_encrypt must be 33 bytes')
    if len(msg) != 32:
        raise ValueError('msg must be 32 bytes')
    if len(ct) != 196:
        raise ValueError('ciphertext must be 196 bytes')

    rv = lib.ecdsaotves_enc_verify(
        context.ctx,
        public_key_sign,
        public_key_encrypt,
        msg,
        ct)

    return True if rv == 1 else False


def ecdsaotves_dec_sig(private_key_encrypt, ct, context=GLOBAL_CONTEXT):
    if len(private_key_encrypt) != 32:
        raise ValueError('private_key_encrypt must be 32 bytes')
    if len(ct) != 196:
        raise ValueError('ciphertext must be 196 bytes')

    output_length = ffi.new('size_t *')
    output_length[0] = 100
    sig_output = ffi.new('unsigned char[{}]'.format(100))

    rv = lib.ecdsaotves_dec_sig(
        context.ctx,
        sig_output,
        output_length,
        private_key_encrypt,
        ct,
    )
    if rv != 1:
        raise ValueError('ecdsaotves_dec_sig failed')

    return bytes(ffi.buffer(sig_output, output_length[0]))


def ecdsaotves_rec_enc_key(public_key_encrypt, ct, sig_der, context=GLOBAL_CONTEXT):

    if len(public_key_encrypt) != 33:
        raise ValueError('public_key_encrypt must be 33 bytes')
    if len(ct) != 196:
        raise ValueError('ciphertext must be 196 bytes')

    key_output = ffi.new('unsigned char[{}]'.format(32))

    sig_length = len(sig_der)
    rv = lib.ecdsaotves_rec_enc_key(context.ctx, key_output, public_key_encrypt, ct, sig_der, sig_length)
    if rv != 1:
        raise ValueError('ecdsaotves_rec_enc_key failed')

    return bytes(ffi.buffer(key_output, 32))
