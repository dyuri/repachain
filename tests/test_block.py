import datetime
from repachain import RepaBlock, InvalidBlockException

import pytest


def test_block_creation():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash")

    assert block.index == 0
    assert block.timestamp == now
    assert block.data == "test"
    assert block.previous_hash == "prevhash"
    assert block.hash is not None

def test_block_creation_with_hash():
    now = datetime.datetime.now()

    with pytest.raises(InvalidBlockException):
        block = RepaBlock(0, now, "test", "prevhash", hash="lol")

def test_block_verify():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash")
    assert block.verify() == True

    with pytest.raises(InvalidBlockException):
        block.hash = "lol"
        block.verify()

def test_block_pow():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash", check_hash=lambda x: x.endswith("0"))

    assert block.hash.endswith("0")

def test_block_as_dict():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash")
    bdict = block.as_dict()

    assert bdict["index"] == 0
    assert bdict["timestamp"] == now.timestamp()
    assert bdict["data"] == "test"
    assert bdict["previous_hash"] == "prevhash"
    assert "nonce" in bdict
    assert "hash" in bdict

def test_block_str():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash", check_hash=lambda x: x.endswith("0"))
    bstr = str(block)
    brepr = repr(block)

    assert bstr == brepr

    assert bstr.startswith("<RepaBlock: 'test' #")
    assert bstr.endswith("0>")
