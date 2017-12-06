#!/usr/bin/env python3

import logcat_parser
from setuptools import setup, find_packages

setup(
    name='logcat_parser',
    version='0.2.3',
    keywords=['adb', 'logcat', 'android', 'logging'],
    description='A parser for Android logcat in binary format.',
    license='GPL',
    author='weiyulan',
    author_email='yulan.wyl@gmail.com',
    url='https://github.com/aheadlead/logcat-parser',
    packages=find_packages(),
    classifiers=(
        'Development Status :: 2 - Pre-Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Testing',
    )
)
