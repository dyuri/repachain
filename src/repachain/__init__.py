import datetime
import copy
import json
import gzip
import sys

from typing import Callable, Optional, Union, List, Any


__all__ = ['RepaBlock', 'RepaChain', 'InvalidBlockException']


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def get_hashlib_alg(algname: str) -> Callable[[List[bytes], bytes], str]:
    import hashlib

    alg = getattr(hashlib, algname, None)

    if not alg:
        sys.exit(f"Cannot use '{algname}' algorithm...")

    def hashfunc(data: List[bytes], nonce: bytes = b'') -> str:
        key = alg()
        for value in data:
            key.update(value)

        key.update(nonce)

        return key.hexdigest()

    return hashfunc


def get_scrypt() -> Callable[[List[bytes], bytes], str]:
    try:
        import scrypt
    except ImportError:
        sys.exit("Cannot import 'scrypt'...")

    def hashfunc(data: List[bytes], nonce: bytes = b'') -> str:
        return scrypt.hash(b'|'.join(data), nonce).hex()

    return hashfunc


class InvalidBlockException(Exception):
    pass


class RepaBlock():

    def __init__(
            self,
            index: int,
            timestamp: datetime.datetime,
            data: str,
            previous_hash: str,
            *,
            hash: str = None,
            nonce: int = 0,
            algorithm: Callable[[List[bytes], bytes], Any] = get_hashlib_alg('sha256'),
            check_hash: Callable[[str], bool] = lambda x: True,
            next_nonce: Callable[[int], int] = lambda n: n + 1) -> None:
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.algorithm = algorithm
        self.check_hash = check_hash
        self.next_nonce = next_nonce

        if hash:
            self.hash = hash
            self.verify()
        else:
            self.hash = self.hashing()

    def verify(self):
        if self.hash != self.calculate_hash():
            raise InvalidBlockException("Wrong hash")

    def calculate_hash(self) -> str:
        return self.algorithm(
            [
                str(self.index).encode('utf-8'),
                str(self.timestamp).encode('utf-8'),
                str(self.data).encode('utf-8'),
                str(self.previous_hash).encode('utf-8')
            ],
            int_to_bytes(self.nonce)
        )

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
        return f"<RepaBlock: '{self.data}' #{self.hash}>"

    def __repr__(self) -> str:
        return str(self)


class RepaChain():

    VERSION = '1.0.0'
    ALGORITHMS = {
        '': get_hashlib_alg('sha256'),
        'sha256': get_hashlib_alg('sha256'),
        'sha3_512': get_hashlib_alg('sha3_512'),
        'scrypt': get_scrypt(),
    }

    def __init__(self,
                 hashending: str = '',
                 algorithm: str = '') -> None:
        self.hashending = hashending
        self.algorithm = algorithm.lower()
        self.blocks = [self.get_genesis_block()]

    def __getitem__(self, i) -> RepaBlock:
        return self.blocks[i]

    def _check_hash(self, hash: str) -> bool:
        return hash.endswith(self.hashending)

    def _get_algorithm(self):
        alg = self.ALGORITHMS.get(self.algorithm, None)
        if alg is None:
            alg = self.ALGORITHMS['']

        return alg

    def get_genesis_block(self) -> RepaBlock:
        genesis_data = {
            "algorithm": self.algorithm,
            "hashending": self.hashending,
            "version": self.VERSION
        }
        return RepaBlock(
            0,
            datetime.datetime.utcnow(),
            json.dumps(genesis_data),
            'arbitrary',
            algorithm=self._get_algorithm(),
            check_hash=self._check_hash
        )

    def add_block(self, data: str) -> None:
        self.blocks.append(
            RepaBlock(
                len(self.blocks),
                datetime.datetime.utcnow(),
                data,
                self.blocks[-1].hash,
                algorithm=self._get_algorithm(),
                check_hash=self._check_hash
            )
        )

    @property
    def chain_size(self) -> int:
        # exclude genesys block
        return len(self.blocks) - 1

    def verify(self) -> bool:
        prevblock = None
        for i, block in enumerate(self.blocks):
            if i == 0:
                # check version and algorithm
                try:
                    bdata = json.loads(block.data)
                    if bdata["version"] != self.VERSION:
                        raise InvalidBlockException(f'Wrong chain version "{bdata.version}"')
                    if bdata["algorithm"] != self.algorithm:
                        raise InvalidBlockException(f'Wrong algorithm "{bdata.algorithm}"')
                except (json.decoder.JSONDecodeError, KeyError):
                    raise InvalidBlockException('Invalid genesis block')

                prevblock = block
                continue

            if prevblock:
                if block.index != i:
                    raise InvalidBlockException(f'Wrong block index at block {i}')
                if prevblock.hash != block.previous_hash:
                    raise InvalidBlockException(f'Wrong previous hash at block {i}')
                if block.hash != block.hashing():
                    raise InvalidBlockException(f'Wrong hash at block {i}')
                if prevblock.timestamp > block.timestamp:
                    raise InvalidBlockException(f'Backdating at block {i}')
            else:
                raise InvalidBlockException(f'Empty')

            prevblock = block

        return True

    def serialize(self) -> List[dict]:
        return [block.as_dict() for block in self.blocks]

    def deserialize(self, data: List[dict]) -> None:
        self.blocks = []
        try:
            genesis = json.loads(data[0]["data"])
            self.algorithm = genesis["algorithm"]
            self.hashending = genesis["hashending"]
            if self.VERSION != genesis["version"]:
                raise InvalidBlockException(f'Incompatible chain version "{genesis.version}"')
        except (json.decoder.JSONDecodeError, KeyError):
            raise InvalidBlockException("Invalid genesis data")

        for block in data:
            self.blocks.append(
                RepaBlock(
                    block['index'],
                    datetime.datetime.fromtimestamp(block['timestamp']),
                    block['data'],
                    block['previous_hash'],
                    hash=block['hash'],
                    nonce=block['nonce'],
                    algorithm=self._get_algorithm(),
                    check_hash=self._check_hash
                )
            )

    def to_json(self) -> str:
        return json.dumps(self.serialize())

    def to_json_file(self, file: str) -> None:
        with gzip.open(file, 'wt', encoding="ascii") as jsonfile:
            json.dump(self.serialize(), jsonfile)

    @classmethod
    def from_json(cls, jsondata: str) -> 'RepaChain':
        self = cls()
        self.deserialize(json.loads(jsondata))

        return self

    @classmethod
    def from_json_file(cls, file: str) -> 'RepaChain':
        self = cls()
        with gzip.open(file, 'rt', encoding="ascii") as jsonfile:
            self.deserialize(json.load(jsonfile))

        return self

    def fork(self, head: Union[str, int] = 'latest') -> 'RepaChain':
        if head in ['latest', 'whole', 'all']:
            return copy.deepcopy(self)

        head = int(head)
        forked = copy.deepcopy(self)
        forked.blocks = forked.blocks[0:head + 1]
        return forked

    def get_root(self, chain: 'RepaChain') -> 'RepaChain':
        min_chain_size = min(self.chain_size, chain.chain_size)
        for i in range(1, min_chain_size):
            if self.blocks[i] != chain.blocks[i]:
                return self.fork(i - 1)

        return self.fork(min_chain_size)
