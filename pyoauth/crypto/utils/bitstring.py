#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    reduce(lambda a, b: a + b, [1, 2, 3, 4])
except Exception:
    from functools import reduce


def bits_to_long(bits):
    """
    Converts a bit sequence to a long value.

    :param bits:
        Bit sequence.
    :returns:
        Long value.
    """
    return reduce(lambda x, y: (x << 1) + y, bits)

