import pytest

from coincurve.ed25519 import get_valid_secret, ed25519_get_pubkey


def test_ed25519(samples):

    vk = get_valid_secret()
    pk = ed25519_get_pubkey(vk)
    assert (len(pk) == 32)


if __name__ == '__main__':
    pytest.main(['-s', __file__])
