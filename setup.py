#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Python module that implements the OAuth protocol for clients
and servers.

More information at http://github.com/gorakhargosh/pyoauth
"""

from setuptools import setup

setup(
    name="pyoauth",
    version="0.0.1",
    license="Apache Software License",
    url="http://github.com/gorakhargosh/pyoauth",
    description="Python OAuth implementation for clients and servers",
    long_description=__doc__,
    author="Yesudeep Mangalapilly",
    author_email="yesudeep@gmail.com",
    zip_safe=True,
    platforms="any",
    packages=["pyoauth"],
    include_package_data=True,
    install_requires=[
        "PyCrypto >=2.3"
    ],
    keywords=' '.join([
        "python",
        "oauth",
        "oauth1",
        "oauth2",
        "client",
        "server",
        "rfc5849",
    ]),
    classifiers=[
        "Development Status :: 2 - Pre-Alpha Development Status",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ]
)
