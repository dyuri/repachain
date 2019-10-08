import timeit

TESTCASES = [
    ('', 'sha256'),
    ('', 'sha3_512'),
    ('', 'scrypt'),
    ('a', 'sha256'),
    ('a', 'sha3_512'),
    ('a', 'scrypt'),
    ('abc', 'sha256'),
    ('abc', 'sha3_512'),
    # ('abc', 'scrypt'),  # well...
]

for tc in TESTCASES:
    testcode = f"""
from repachain import RepaChain

bc = RepaChain('{tc[0]}', '{tc[1]}')
for i in range(10):
    bc.add_block(f'block {{i}}')
"""

    tm = timeit.timeit(testcode, number=100)
    print(f"testcase {tc[1]} / '{tc[0]}': {tm}")
