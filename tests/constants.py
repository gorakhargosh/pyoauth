#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

from mom._compat import have_python3

if have_python3:
    from tests import py3kconstants
    constants = py3kconstants
else:
    from tests import py2kconstants
    constants = py2kconstants

    
__all__ = [
    "constants"
]
