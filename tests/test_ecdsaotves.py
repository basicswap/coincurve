import pytest

from coincurve.ed25519 import get_valid_secret
from coincurve.keys import PublicKey
from coincurve.ecdsaotves import (
    ecdsaotves_enc_sign,
    ecdsaotves_enc_verify,
    ecdsaotves_dec_sig,
    ecdsaotves_rec_enc_key)

import secrets


def test_ecdsaotves(samples):
    vk_sign = get_valid_secret()
    vk_encrypt = get_valid_secret()

    pk_sign = PublicKey.from_secret(vk_sign).format()
    pk_encrypt = PublicKey.from_secret(vk_encrypt).format()
    sign_hash = secrets.token_bytes(32)

    cipher_text = ecdsaotves_enc_sign(vk_sign, pk_encrypt, sign_hash)

    assert (ecdsaotves_enc_verify(pk_sign, pk_encrypt, sign_hash, cipher_text))

    sig = ecdsaotves_dec_sig(vk_encrypt, cipher_text)

    PublicKey.from_secret(vk_sign).verify(sig, sign_hash, hasher=None)

    recovered_key = ecdsaotves_rec_enc_key(pk_encrypt, cipher_text, sig)

    assert (vk_encrypt == recovered_key)


if __name__ == '__main__':
    pytest.main(['-s', __file__])
