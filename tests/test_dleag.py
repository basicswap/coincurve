import pytest

from coincurve.keys import PrivateKey
from coincurve.dleag import dleag_prove, dleag_verify


valid_keydata = b'\x03\xa8\x18+\xed\xe5i\xdf\x9c\xd87\x18\xd6Q\xe7/\xde\xbf\x02Uf\x04\xd1\xf5$\x0c\xaffB\x00\x88!'


def test_dleag(samples):

    vk = PrivateKey(samples['PRIVATE_KEY_BYTES'])
    with pytest.raises(ValueError):
        proof = dleag_prove(vk)

    vk = PrivateKey(valid_keydata)
    proof = dleag_prove(vk)
    assert (dleag_verify(proof) is True)


if __name__ == '__main__':
    pytest.main(['-s', __file__])
