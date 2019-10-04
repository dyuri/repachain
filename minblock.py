import hashlib
import datetime
import copy

from typing import Callable, Union


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


class MinBlock():

    def __init__(
            self,
            index: int,
            timestamp: datetime.datetime,
            data: str,
            previous_hash: str,
            nonce: int = 0,
            check_hash: Callable[[str], bool] = lambda x: True,
            next_nonce: Callable[[int], int] = lambda n: n + 1) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.check_hash = check_hash
        self.next_nonce = next_nonce

        self.hash = self.hashing()

    def calculate_hash(self) -> str:
        key = hashlib.sha256()
        key.update(str(self.index).encode('utf-8'))
        key.update(str(self.timestamp).encode('utf-8'))
        key.update(str(self.data).encode('utf-8'))
        key.update(str(self.previous_hash).encode('utf-8'))
        key.update(int_to_bytes(self.nonce))

        return key.hexdigest()

    def hashing(self) -> str:
        key = self.calculate_hash()

        while not self.check_hash(key):
            self.nonce = self.next_nonce(self.nonce)
            key = self.calculate_hash()

        return key

    def as_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp.timestamp(),
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash,
        }

    def __str__(self) -> str:
        return f"<MinBlock: '{self.data}' #{self.hash}>"

    def __repr__(self) -> str:
        return str(self)


# TODO
# - save / restore
class MinChain():

    def __init__(self, hashending: str = '') -> None:
        self.hashending = hashending
        self.blocks = [self.get_genesis_block()]

    def __getitem__(self, i) -> MinBlock:
        return self.blocks[i]

    def _check_hash(self, hash: str) -> bool:
        return hash.endswith(self.hashending)

    def log(self, message: str) -> None:
        # TODO
        print(message)

    def get_genesis_block(self) -> MinBlock:
        return MinBlock(
            0,
            datetime.datetime.utcnow(),
            'Genesis',
            'arbitrary',
            check_hash=self._check_hash
        )

    def add_block(self, data: str) -> None:
        self.blocks.append(
            MinBlock(
                len(self.blocks),
                datetime.datetime.utcnow(),
                data,
                self.blocks[-1].hash,
                check_hash=self._check_hash
            )
        )

    def get_chain_size(self) -> int:
        # exclude genesys block
        return len(self.blocks) - 1

    def verify(self) -> bool:
        prevblock = None
        for i, block in enumerate(self.blocks):
            if i == 0:
                # skip genesis block
                prevblock = block
                continue

            if prevblock:
                if block.index != i:
                    self.log(f'Wrong block index at block {i}')
                    return False
                if prevblock.hash != block.previous_hash:
                    self.log(f'Wrong previous hash at block {i}')
                    return False
                if block.hash != block.hashing():
                    self.log(f'Wrong hash at block {i}')
                    return False
                if prevblock.timestamp > block.timestamp:
                    self.log(f'Backdating at block {i}')
            else:
                self.log(f'Empty')
                return False

            prevblock = block

        return True

    def fork(self, head: Union[str, int] ='latest') -> 'MinChain':
        if head in ['latest', 'whole', 'all']:
            return copy.deepcopy(self)

        head = int(head)
        forked = copy.deepcopy(self)
        forked.blocks = forked.blocks[0:head + 1]
        return forked

    def get_root(self, chain: 'MinChain') -> 'MinChain':
        min_chain_size = min(self.get_chain_size(), chain.get_chain_size())
        for i in range(1, min_chain_size):
            if self.blocks[i] != chain.blocks[i]:
                return self.fork(i - 1)

        return self.fork(min_chain_size)
