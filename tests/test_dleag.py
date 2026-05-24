import pytest

from coincurve.keys import PrivateKey
from coincurve.dleag import (
    dleag_prove,
    dleag_verify,
    dleag_prove_gen,
    dleag_verify_gen,
)


valid_keydata = b'\x03\xa8\x18+\xed\xe5i\xdf\x9c\xd87\x18\xd6Q\xe7/\xde\xbf\x02Uf\x04\xd1\xf5$\x0c\xaffB\x00\x88!'

# standard ed25519 base point B and the alternate generator B2.
ED25519_B = bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666')
ED25519_B2 = bytes.fromhex('13b663e5e06bf5301c77473bb2fc5beb51e4046e9b7efef2f6d1a324cb8b1094')


def test_dleag(samples):

    vk = PrivateKey(samples['PRIVATE_KEY_BYTES'])
    with pytest.raises(ValueError):
        proof = dleag_prove(vk)

    vk = PrivateKey(valid_keydata)
    proof = dleag_prove(vk)
    assert (dleag_verify(proof) is True)


def test_dleag_gen_matches_hardcoded():
    # standard B and B2 must produce the same proof as the hardcoded path and verify under both.
    vk = PrivateKey(valid_keydata)
    nonce = bytes(range(32))
    p_hard = dleag_prove(vk, nonce_bytes=nonce)
    p_gen = dleag_prove_gen(vk, ED25519_B, ED25519_B2, nonce_bytes=nonce)
    assert p_gen == p_hard
    assert dleag_verify(p_gen) is True
    assert dleag_verify_gen(p_gen, ED25519_B, ED25519_B2) is True


def test_dleag_gen_alternate_generators():
    # An alternate generator pair round trips and is rejected under the standard pair.
    vk = PrivateKey(valid_keydata)
    proof = dleag_prove_gen(vk, ED25519_B2, ED25519_B)
    assert dleag_verify_gen(proof, ED25519_B2, ED25519_B) is True
    assert dleag_verify_gen(proof, ED25519_B, ED25519_B2) is False


def test_dleag_gen_invalid_generator_length():
    vk = PrivateKey(valid_keydata)
    with pytest.raises(ValueError):
        dleag_prove_gen(vk, ED25519_B[:31], ED25519_B2)
    with pytest.raises(ValueError):
        dleag_verify_gen(b'\x00' * 100, ED25519_B[:31], ED25519_B2)


def test_dleag_gen_invalid_nonce_length():
    vk = PrivateKey(valid_keydata)
    with pytest.raises(ValueError):
        dleag_prove_gen(vk, ED25519_B, ED25519_B2, nonce_bytes=b'\x00' * 31)


if __name__ == '__main__':
    pytest.main(['-s', __file__])
