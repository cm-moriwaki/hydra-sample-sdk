from setuptools import setup, find_packages

setup(
    name='hydra_sdk',
    version='0.0.1',
    description='hydra sdk',
    long_description='hydra sdk for python',
    packages=find_packages(),
    install_requires=[
        'requests',
        'python-jose',
        'pycrypto',
    ],
    tests_require=['nose'],
    test_suite='nose.collector'
)
