import datetime
from repachain import RepaBlock

import pytest


def test_block_creation():
    now = datetime.datetime.now()
    block = RepaBlock(0, now, "test", "prevhash")

    assert block.index == 0
