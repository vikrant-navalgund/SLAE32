#! /usr/bin/env python
import argparse
import random

def keygen():
    return random.randbytes(32)


def txt2byteKey(text):
    if len(text) < 32:
        print('\n[-] Error: Key length should be 32-bytes')
        exit(0)
    elif len(text) > 32:
        print('\n[!] Warning: Key length truncated to 32-bytes')
    return bytes(text, 'utf-8')[:32]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='GOST-keygen.py',
                                      description='keygen for the GOST cipher')
    parser.add_argument('-i', '--input', help='input key string of utf-8 text')
    parser.add_argument('-o', '--output', help='output byte buffer to file')
    args = parser.parse_args()

    filename = 'key.bin' if args.output == None else args.output

    with open(filename, 'wb') as fw:
        if args.input == None:
            fw.write(keygen())
        else:
            fw.write(txt2byteKey(args.input))

    print('\n[+] Key file written successfully: {}'.format(filename))
