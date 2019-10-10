import importlib
import datetime
import copy
import json
import gzip

from typing import Callable, Union, List, Any


__all__ = ['RepaBlock', 'RepaChain', 'InvalidBlockException', 'AlgorithmMissingException']


class InvalidBlockException(Exception):
    pass


class AlgorithmMissingException(Exception):
    pass


def int_to_bytes(n: int) -> bytes:
    return n.to_bytes((n.bit_length() + 7) // 8, 'big')


def get_hashlib_alg(algname: str) -> Callable[[List[bytes], bytes], str]:
    hashlib = importlib.import_module('hashlib')

    alg = getattr(hashlib, algname, None)

    if not alg:
        raise AlgorithmMissingException(f"Cannot use '{algname}' algorithm")

    def hashfunc(data: List[bytes], nonce: bytes = b'') -> str:
        key = alg()
        for value in data:
            key.update(value)

        key.update(nonce)

        return key.hexdigest()

    return hashfunc


def get_scrypt() -> Callable[[List[bytes], bytes], str]:
    try:
        scrypt = importlib.import_module('scrypt')
    except ImportError:
        raise AlgorithmMissingException("Cannot import 'scrypt'")

    def hashfunc(data: List[bytes], nonce: bytes = b'') -> str:
        return scrypt.hash(b'|'.join(data), nonce).hex()

    return hashfunc


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
        return True

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
        '': (lambda: get_hashlib_alg('sha256')),
        'sha256': (lambda: get_hashlib_alg('sha256')),
        'sha3_512': (lambda: get_hashlib_alg('sha3_512')),
        'scrypt': get_scrypt,
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

        return alg()

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
            if not prevblock:
                # check version and algorithm
                try:
                    bdata = json.loads(block.data)
                    if bdata["version"] != self.VERSION:
                        raise InvalidBlockException(f'Wrong chain version "{bdata["version"]}"')
                    if bdata["algorithm"] != self.algorithm:
                        raise InvalidBlockException(f'Wrong algorithm "{bdata["algorithm"]}"')
                except (json.decoder.JSONDecodeError, KeyError):
                    raise InvalidBlockException('Invalid genesis block')
            else:
                if block.index != i:
                    raise InvalidBlockException(f'Wrong block index at block {i}')
                if prevblock.hash != block.previous_hash:
                    raise InvalidBlockException(f'Wrong previous hash at block {i}')
                if prevblock.timestamp > block.timestamp:
                    raise InvalidBlockException(f'Backdating at block {i}')

            block.verify()

            prevblock = block

        return True

    def serialize(self) -> List[dict]:
        return [block.as_dict() for block in self.blocks]

    @classmethod
    def deserialize(cls, data: List[dict]) -> 'RepaChain':
        try:
            genesis = json.loads(data[0]["data"])
            if cls.VERSION != genesis["version"]:
                raise InvalidBlockException(f'Incompatible chain version "{genesis["version"]}"')
        except (json.decoder.JSONDecodeError, KeyError):
            raise InvalidBlockException("Invalid genesis data")

        chain = cls(genesis["hashending"], genesis["algorithm"])
        chain.blocks = []

        for block in data:
            chain.blocks.append(
                RepaBlock(
                    block['index'],
                    datetime.datetime.fromtimestamp(block['timestamp']),
                    block['data'],
                    block['previous_hash'],
                    hash=block['hash'],
                    nonce=block['nonce'],
                    algorithm=chain._get_algorithm(),
                    check_hash=chain._check_hash
                )
            )

        return chain

    def to_json(self) -> str:
        return json.dumps(self.serialize())

    def to_json_file(self, file: str) -> None:
        with gzip.open(file, 'wt', encoding="ascii") as jsonfile:
            json.dump(self.serialize(), jsonfile)

    @classmethod
    def from_json(cls, jsondata: str) -> 'RepaChain':
        return cls.deserialize(json.loads(jsondata))

    @classmethod
    def from_json_file(cls, file: str) -> 'RepaChain':
        with gzip.open(file, 'rt', encoding="ascii") as jsonfile:
            chain = cls.deserialize(json.load(jsonfile))

        return chain

    def fork(self, head: Union[str, int] = 'latest') -> 'RepaChain':
        if head in ['latest', 'whole', 'all']:
            return copy.deepcopy(self)

        head = int(head)
        forked = copy.deepcopy(self)
        forked.blocks = forked.blocks[0:head + 1]
        return forked

    def get_root(self, chain: 'RepaChain') -> 'RepaChain':
        min_chain_size = min(self.chain_size, chain.chain_size)
        for i in range(1, min_chain_size + 1):
            if self.blocks[i].hash != chain.blocks[i].hash:
                return self.fork(i - 1)

        return self.fork(min_chain_size)
