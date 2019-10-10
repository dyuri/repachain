from repachain import RepaChain, RepaBlock, InvalidBlockException
import os

import pytest


def test_chain_creation():
    chain = RepaChain()

    assert isinstance(chain[0], RepaBlock)

def test_chain_alg_fallback():
    chain = RepaChain(algorithm='lol')

    assert chain._get_algorithm()([b'lol']) == chain.ALGORITHMS['']()([b'lol'])

def test_chain_algorithms():
    for alg in RepaChain.ALGORITHMS:
        chain = RepaChain(algorithm=alg)
        assert isinstance(chain[0], RepaBlock)

def test_chain_add_block():
    chain = RepaChain()
    chain.add_block("lol")

    assert chain.chain_size == 1
    assert isinstance(chain[1], RepaBlock)
    assert chain[1].data == "lol"

def test_chain_verify_ok():
    chain = RepaChain()
    chain.add_block("lol")

    assert chain.verify()

def test_chain_verify_version_mismatch():
    orig_version = RepaChain.VERSION
    RepaChain.VERSION = '11212.121.1'
    chain = RepaChain()
    RepaChain.VERSION = orig_version
    chain.add_block("lol")

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_verify_algorithm_mismatch():
    chain = RepaChain()
    chain.algorithm = 'sha3_512'
    chain.add_block("lol")

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_verify_wrong_genesis_block():
    chain = RepaChain()
    chain.add_block("lol")
    chain.blocks[0] = chain.blocks[1]

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_verify_index_mismatch():
    chain = RepaChain()
    chain.add_block("lol")
    chain.blocks[1].index = 12

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_verify_prev_hash_mismatch():
    chain = RepaChain()
    chain.add_block("lol")
    chain.blocks[1].previous_hash = 'lol'

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_verify_timestamp():
    chain = RepaChain()
    chain.add_block("lol")
    chain.add_block("lol2")
    chain.blocks[2].timestamp = chain.blocks[0].timestamp

    with pytest.raises(InvalidBlockException):
        chain.verify()

def test_chain_serialize():
    chain = RepaChain()
    chain.add_block("lol")

    blocklist = chain.serialize()
    assert blocklist[0]["hash"] == chain[0].hash
    assert blocklist[0]["data"] == chain[0].data
    assert blocklist[0]["index"] == 0
    assert blocklist[1]["hash"] == chain[1].hash

def test_chain_deserialize():
    chain = RepaChain()
    chain.add_block("lol")

    chain2 = RepaChain.deserialize(chain.serialize())

    assert chain != chain2
    assert chain.algorithm == chain2.algorithm
    assert chain.hashending == chain2.hashending
    assert chain.chain_size == chain2.chain_size
    assert chain[0].hash == chain2[0].hash
    assert chain[1].hash == chain2[1].hash

def test_chain_deserialize_incompatible_version():
    chain = RepaChain()
    chain.add_block("lol")
    old_version = RepaChain.VERSION
    RepaChain.VERSION = 'lol'

    with pytest.raises(InvalidBlockException):
        chain2 = RepaChain.deserialize(chain.serialize())

    RepaChain.VERSION = old_version

def test_chain_deserialize_invalid_genesis_block():
    chain = RepaChain()
    chain.add_block("lol")
    blocklist = chain.serialize()
    blocklist[0]["data"] = "lol"

    with pytest.raises(InvalidBlockException):
        chain2 = RepaChain.deserialize(blocklist)

def test_chain_serialize_json():
    chain = RepaChain()
    chain.add_block("lol")

    jsondata = chain.to_json()
    assert type(jsondata) == str

    chain2 = RepaChain.from_json(jsondata)

    assert chain != chain2
    assert chain.algorithm == chain2.algorithm
    assert chain.hashending == chain2.hashending
    assert chain.chain_size == chain2.chain_size
    assert chain[0].hash == chain2[0].hash
    assert chain[1].hash == chain2[1].hash

def test_chain_serialize_json_file(tmpdir):
    chain = RepaChain()
    chain.add_block("lol")
    jsonfile = os.path.join(tmpdir, "chain.json.gz")

    chain.to_json_file(jsonfile)
    chain2 = RepaChain.from_json_file(jsonfile)

    assert chain != chain2
    assert chain.algorithm == chain2.algorithm
    assert chain.hashending == chain2.hashending
    assert chain.chain_size == chain2.chain_size
    assert chain[0].hash == chain2[0].hash
    assert chain[1].hash == chain2[1].hash

def test_chain_fork():
    chain = RepaChain()
    chain.add_block("lol")

    chain2 = chain.fork()

    assert chain != chain2
    assert chain.algorithm == chain2.algorithm
    assert chain.hashending == chain2.hashending
    assert chain.chain_size == chain2.chain_size
    assert chain[0].hash == chain2[0].hash
    assert chain[1].hash == chain2[1].hash

def test_chain_fork_length():
    chain = RepaChain()
    chain.add_block("lol")
    chain.add_block("lol2")

    chain2 = chain.fork(1)

    assert chain != chain2
    assert chain.algorithm == chain2.algorithm
    assert chain.hashending == chain2.hashending
    assert chain.chain_size == chain2.chain_size + 1
    assert chain[0].hash == chain2[0].hash
    assert chain[1].hash == chain2[1].hash

def test_chain_root_sub():
    chain = RepaChain()
    chain.add_block("lol")
    chain.add_block("lol2")

    chain2 = chain.fork(1)

    rootchain = chain.get_root(chain2)

    assert chain != chain2
    assert chain != rootchain
    assert chain2 != rootchain
    assert chain.algorithm == rootchain.algorithm
    assert chain.hashending == rootchain.hashending
    assert chain.chain_size == rootchain.chain_size + 1
    assert chain2.chain_size == rootchain.chain_size
    assert chain[1].hash == rootchain[1].hash
    assert chain2[1].hash == rootchain[1].hash

def test_chain_root_not_sub():
    chain = RepaChain()
    chain.add_block("lol")
    chain.add_block("lol2")

    chain2 = chain.fork(1)
    chain2.add_block("lol3")

    rootchain = chain.get_root(chain2)

    assert chain != chain2
    assert chain != rootchain
    assert chain2 != rootchain
    assert chain.algorithm == rootchain.algorithm
    assert chain.hashending == rootchain.hashending
    assert chain.chain_size == rootchain.chain_size + 1
    assert chain2.chain_size == rootchain.chain_size + 1
    assert chain[1].hash == rootchain[1].hash
    assert chain2[1].hash == rootchain[1].hash
