from setuptools import setup, find_packages

try:
    with open('README.md') as fh:
        LONG_DESC = fh.read()
except (IOError, OSError):
    LONG_DESC = ''

setup(
    name="repachain",
    version='1.0.2',
    url='https://github.com/dyuri/minchain',
    license='MIT',
    author='Gyuri Horák',
    author_email='dyuri@horak.hu',
    description='Minimal blockchain',
    long_description=LONG_DESC,
    long_description_content_type='text/markdown',
    packages=find_packages("src"),
    package_dir={"": "src"},
    platforms='any',
    python_requires=">=3.6",
    data_files=[("", ["LICENSE.txt"])],
    classifiers=[
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'License :: OSI Approved :: MIT License',
    ]
)
