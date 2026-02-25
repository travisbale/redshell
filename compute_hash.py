#!/usr/bin/python

import numpy
import sys


def rotate_string(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1

    return int(binb, 2)


if __name__ == "__main__":
    try:
        esi = sys.argv[1]
    except IndexError:
        print(f"Usage: {sys.argv[0]} <inputstring>")
        sys.exit()

    # Initialize variables
    edx = 0x0
    ror_count = 0

    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi) - 1:
            edx = rotate_string(edx, 0xD)

        ror_count += 1

    print(hex(edx))
