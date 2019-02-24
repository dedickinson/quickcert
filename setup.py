import os
import sys
from setuptools import setup

from setuptools.command.test import test as TestCommand

here = os.path.abspath(os.path.dirname(__file__))

PACKAGE_NAME = 'quickcert'

packages = [PACKAGE_NAME]

requires = [
    'cryptography>=2.5',
    'python-interface>=1.5'
]

test_requirements = [
    'pytest-cov>=2.6',
    'pytest>=4.2'
]

entry_points = {}

#entry_points = {
#    'console_scripts': [
#        'qcert = quickcert.cli'
#    ]
#},

about = {}

with open(os.path.join(here, PACKAGE_NAME, '__version__.py'), mode='r', encoding='utf-8') as f:
    exec(f.read(), about)


with open('README.md', 'r') as fh:
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
    package_data={'': ['LICENSE']},
    package_dir={PACKAGE_NAME: PACKAGE_NAME},
    include_package_data=True,
    python_requires='>=3.6',
    install_requires=requires,
    tests_require=test_requirements,
    classifiers=[
        'Programming Language :: Python :: 3',
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Topic :: Security :: Cryptography'
    ]
)
