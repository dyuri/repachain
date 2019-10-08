# MinChain - minimal blockchain

For experimenting and future projects.

## Requirements

  - Python 3.6+
  - *[optional]* [scrypt](https://pypi.org/project/scrypt/) for scrypt based hashing

## Install

```
$ pip install --user repachain
```

or (using latest available code)

```
$ pip install --user git+https://github.com/dyuri/repachain
```

or

```
$ git clone https://github.com/dyuri/repachain
$ pip install --user repachain
```

## Usage

```
>>> from repachain import RepaChain
>>> rc = RepaChain('abc', 'sha256')
>>> rc.add_block('whatever')
>>> rc.verify()
>>> rc.to_json_file('whatever.json.gz')
>>> rc[1].hash = 'wrong hash'
>>> rc.verify()
repachain.InvalidBlockException: Wrong hash at block 1
>>> rc2 = RepaChain.from_json_file('whatever.json.gz')
>>> rc2.verify()
>>> rc2[1].data
'whatever'
```

## TODO

  - proper documentation
  - tests
