import os
import sys
from setuptools import setup

PACKAGE_NAME = 'quickcert'
here = os.path.abspath(os.path.dirname(__file__))

packages = [PACKAGE_NAME]

requires = [
    'cryptography>=2.5',
    'numpy>=1.16'
]

test_requirements = [
    'pytest-cov>=2.6',
    'pytest>=4.2'
]

classifiers = [
    "Programming Language :: Python :: 3",
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: BSD License",
    "Operating System :: OS Independent",
    "Topic :: Security :: Cryptography",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3",
]

entry_points = {
    'console_scripts': [
        'qcert = quickcert.cli'
    ]
},

about = {}

with open(os.path.join(here, PACKAGE_NAME, '__version__.py'), mode='r', encoding='utf-8') as f:
    exec(f.read(), about)


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name=about['__title__'],
    version=about['__version__'],
    description=about['__description__'],
    long_description=long_description,
    long_description_content_type='text/markdown',
    author=about['__author__'],
    author_email=about['__author_email__'],
    url=about['__url__'],
    license=about['__license__'],
    packages=packages,
    package_data={'': ['LICENSE', 'NOTICE'], 'requests': ['*.pem']},
    package_dir={PACKAGE_NAME: PACKAGE_NAME},
    include_package_data=True,
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*",
    install_requires=requires,
    tests_require=test_requirements,
    classifiers=classifiers
)
