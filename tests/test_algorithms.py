import pytest
from repachain import get_hashlib_alg, get_scrypt, AlgorithmMissingException


def test_sha256():
    alg = get_hashlib_alg('sha256')
    hashres_n0 = alg([b'lol'])
    hashres_n1 = alg([b'lol'], b'1')
    assert len(hashres_n0) == 64
    assert len(hashres_n1) == 64
    assert hashres_n0 != hashres_n1

def test_missing_alg():
    with pytest.raises(AlgorithmMissingException):
        get_hashlib_alg('lol')

def test_scrypt():
    alg = get_scrypt()
    hashres_n0 = alg([b'lol'])
    hashres_n1 = alg([b'lol'], b'1')
    assert hashres_n0 is not None
    assert hashres_n1 is not None
    assert hashres_n0 != hashres_n1
