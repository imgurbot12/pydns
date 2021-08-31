from setuptools import setup

#TODO: unit-tests need to be a thing for all of the existing
#TODO: after unit-tests join struct operations into groups when possible
#TODO: investigate pypacker to learn how they parse domains fast

setup(
    name='pydns',
    version='0.0.3',
    packages=[
        'pydns',
        'pydns.ddns',
        'pydns.edns',
        'pydns.dnssec',
        'pydns.records',
        'pydns.client',
        'pydns.server',
    ],
    author='imgurbot12',
    author_email='imgurbot12@gmail.com',
    url='https://github.com/imgurbot12/pydns',
    license='MIT',
    description="a small dns packet library designed for both parsing/creation"
)
