#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Yesudeep Mangalapilly <yesudeep@gmail.com>
# Copyright (C) 2012 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


"""
Python module that implements the OAuth protocol for clients
and servers.

More information at http://github.com/gorakhargosh/pyoauth
"""

from setuptools import setup

import logging
logging.warning("Alpha development. install_requires is disabled. Undo this "
                "when you're done.")

setup(
    name="pyoauth",
    version="0.0.1",
    license="Apache Software License",
    url="http://github.com/gorakhargosh/pyoauth",
    description="Python OAuth implementation for clients and servers",
    long_description=__doc__,
    author="Yesudeep Mangalapilly",
    author_email="yesudeep@google.com",
    zip_safe=True,
    platforms="any",
    packages=["pyoauth"],
    include_package_data=True,
    install_requires=[
    #    "mom >=0.0.1",
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
