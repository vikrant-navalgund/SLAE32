#! /usr/bin/env python
import argparse


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='GOST-keygen.py',
                                      description='keygen for the GOST cipher')
    parser.add_argument('-i', '--input', help='input file with utf-8 text')
    parser.add_argument('-o', '--output', help='output byte buffer to file')
    args = parser.parse_args()

    filename = 'data.bin' if args.output == None else args.output

    if args.input == None:
        print('[-] Error: No input text file specified, exiting !')
        exit(0)

    with open(args.input, 'rt') as fr, open(filename, 'wb') as fw:
        fw.write(bytes(fr.read(), 'utf-8'))

    print('\n[+] Text file converted to byte buffer successfully: {}'.format(filename))