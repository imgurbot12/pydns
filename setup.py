from setuptools import setup

setup(
    name='pydns',
    version='0.0.1',
    packages=[
        'pydns',
        'pydns.edns',
        'pydns.records',
        'pydns.server'
    ],
    author='imgurbot12',
    author_email='imgurbot12@gmail.com',
    url='https://github.com/wcember/pypub',
    license='MIT',
    description="a small dns packet library designed for both parsing/creation"
)
