#!/usr/bin/python

import hashlib, sys

if len(sys.argv) != 2:
    print("Ha habido un error...\n")
    sys.exit(1)

if __name__ == '__main__':
    palabra = sys.argv[1]
    md5 = hashlib.md5(palabra.encode()).hexdigest()
    print(md5)
