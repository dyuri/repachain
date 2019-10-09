from repachain import RepaChain, RepaBlock, InvalidBlockException

import pytest


def test_chain_creation():
    chain = RepaChain()

    assert isinstance(chain[0], RepaBlock)

def test_chain_alg_fallback():
    chain = RepaChain(algorithm='lol')

    assert chain._get_algorithm()([b'lol']) == chain.ALGORITHMS['']()([b'lol'])
