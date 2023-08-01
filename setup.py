from setuptools import setup, find_packages

with open('README.md', 'r') as f:
    readme = f.read()

setup(
    name='pydns3',
    version='0.0.9',
    license='MIT',
    packages=find_packages(),
    url='https://github.com/imgurbot12/pydns',
    author='Andrew Scott',
    author_email='imgurbot12@gmail.com',
    description='Simple Python DNS Library. DNS Packet-Parsing/Client/Server',
    python_requires='>=3.8',
    long_description=readme,
    long_description_content_type="text/markdown",
    install_requires=[
        'pypool3>=0.0.2',
        'pyderive3>=0.0.6',
        'pystructs3>=0.0.7',
        'pyserve3>=0.0.7',
        'typing_extensions>=4.7.1',
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ]
)
