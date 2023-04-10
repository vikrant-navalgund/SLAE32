#!/usr/bin/env python
import argparse
import random
import fixedint
from art import *
from struct import pack, unpack

''' This is an example implementation of the GOST Block Cipher Enc/Dec algorithm.
    Specific verion of GOST 28147-89 in ECB mode *ONLY*
    Author: @vikrant
'''
# 256-bit/32 bytes psuedo random key
PSUEDO_RANDOM_KEY = b''

# GOST CONSTS
GOST_ROUNDS = 32
GOST_ENCRYPT = 'encrypt'
GOST_DECRYPT = 'decrypt'

# Key Data Store(KDS)
key_space = ''

# GOST S-Boxes generated using a PRF - using the tool CrypTool2
sBoxesRandom = [  
    0xC, 0xF, 0xD, 0x8, 0x5, 0x4, 0xA, 0xC, 0xF, 0xE, 0xB, 0xD, 0x5, 0x2, 0xE, 0x3,
    0x1, 0xE, 0x6, 0x0, 0xF, 0x9, 0x9, 0x3, 0x8, 0xC, 0x2, 0x0, 0x1, 0x5, 0xA, 0x9,
    0x5, 0x1, 0x9, 0xF, 0xD, 0x8, 0xC, 0x0, 0xD, 0xC, 0xC, 0xA, 0xC, 0xF, 0x5, 0xF,
    0x0, 0xB, 0xF, 0xD, 0x1, 0xC, 0xD, 0x2, 0xF, 0x3, 0x0, 0x5, 0xB, 0xF, 0x1, 0xD,
    0x2, 0x4, 0xE, 0x5, 0x1, 0xC, 0x7, 0x3, 0x9, 0x5, 0x8, 0x8, 0x7, 0xF, 0x7, 0x2, 
    0x1, 0x0, 0xC, 0x1, 0x5, 0xB, 0xA, 0x4, 0xB, 0x5, 0xE, 0x4, 0xB, 0xA, 0x4, 0xA, 
    0x8, 0x9, 0xD, 0x2, 0x3, 0x0, 0x3, 0xB, 0xA, 0xC, 0xC, 0x8, 0x1, 0xB, 0xE, 0xD, 
    0xE, 0x5, 0x3, 0x9, 0x0, 0x9, 0xB, 0xE, 0x0, 0x5, 0x1, 0x3, 0x7, 0xF, 0x2, 0x5 
]

# GOST S-Boxes Central Bank of Russian Federation - DEFAULT 
sBoxes = [ 
    0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3,
    0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
	0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
	0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
	0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
	0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
	0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
	0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC 
]
 

# Get Random key - 32 bytes - use for generating a random key 
def getRandomKey():
    return random.randbytes(32)


# Key scheduling Algorithm
def getKeys(inputKey):
    keys = inputKey
    #print('\nKey: {}\nKey length: {} bytes'.format(keys, len(keys)))
    print('\nKey length: {} bytes'.format(len(keys)))
    x = [] 
    for i in range(0, len(keys), 4):
        x.append(keys[i:i+4])
    return x[::-1]


# PKCS7 padding or some variant of PKCS7? Not sure really!
def pkcs7Padding(inputBuffer):
    padBytes = (8 - (len(inputBuffer) % 8)) + 8
    return inputBuffer + (pack('<B', padBytes) * padBytes)


# PKCS7 un-padding or some variant of PKCS7? Not sure really!
def pkcs7Unpadding(inputBuffer):
    n = inputBuffer[-1]
    if inputBuffer.endswith(bytes([n] * n)):
        inputBuffer = inputBuffer[:-n]
    return inputBuffer    


'''
Chunk the input buffer into 64-bit blocks and start
the cipher rounds. The general algorithm is as follows.
Xj : jth Key 
*K : operation with s-box
*R : circular left shift <<< 11
a  : Left half of the Data
b  : Right half of the Data

Encryption:
| a(j) = (a(j-1) [+] X(j-1)(mod 8))*K*R (+) b (j-1)
|                                                      j = 1..24;
| b(j) = a(j-1)

| a(j) = (a(j-1) [+] X(32-j))*K*R (+) b(j-1)
|                                              25..31; a32 = a31;
| b(j) = a(j-1)

b(32) = (a(31) [+] X0)*K*R (+) b(31) j=32,

Decryption:
| a(32-j) = (a(32-j+1) [+] X(j-1))*K*R (+) b(32-j+1)
|                                                       j = 1..8;
| b(32-1) = a(32-j+1)

| a(32-j) = (a(32-j+1) [+] X(j-1)(mod 8))*K*R (+) b(32-j+1)
|                                                       j = 9..31;
| b(32-1) = a(32-j+1)

| a(0) = a(1)
|                                                           j=32.
| b(0) = (a(1) [+] X0)*K*R (+) b1

'''
def gostRound(L, R, n, mode):
    Li = R

    if mode == GOST_ENCRYPT:
        Ki = key_space[n % 8 if n < 24 else 7 - (n % 8)] 
    elif mode == GOST_DECRYPT:
        Ki = key_space[n % 8 if n < 8 else 7 - (n % 8)]

    Ni = (unpack('<I', R)[0] + unpack('<I', Ki)[0]) % (2**32)
    Ni = pack('<I', Ni)[::-1]

    j = 0
    rF = b''
    for i in range(len(Ni)):
        Nt = Ni[i:i+1]
        Nf1 = sBoxes[j * 16 + (unpack('<B', Nt)[0] & 0xf0) >> 4]
        Nf2 = sBoxes[(j+1) * 16 + (unpack('<B', Nt)[0] & 0x0f)]
        Nf = (Nf1 << 4 ) | (Nf2)
        rF = rF + pack('<B', Nf) 
        j = j + 2

    rF = unpack('<I', rF)[0]
    rF1 = fixedint.UInt32(rF) << 11
    rF2 = fixedint.UInt32(rF) >> (32 -21) 
    rF = rF1 | rF2

    rF = rF ^ unpack('<I', L)[0]     
    return (Li, pack('<I', rF))


# GOST Encrypt
def dataEncrypt(input):
    print('\nGOST - ECB mode : Encrypt')
    processedText = b''
    input = pkcs7Padding(input)[::-1]
    numBlocks = len(input)//8
    print('64-bit blocks: {}'.format(numBlocks))
    for i in range(numBlocks):
        R0 = input[(i*8):(i*8)+4][::-1]
        L0 = input[(i*8)+4:(i*8)+8][::-1]
        Li, Ri = L0, R0
        for i in range(GOST_ROUNDS):
            Li, Ri = gostRound(Li, Ri, i, GOST_ENCRYPT)
        #print('L32: {}\t R32: {}'.format(Ri, Li))
        processedText = Li[::-1] + Ri[::-1] + processedText
    return processedText


# GOST Decrypt
def dataDecrypt(input):
    print('\nGOST - ECB mode : Decrypt')
    processedText = b''
    numBlocks = len(input)//8
    print('64-bit blocks: {}'.format(numBlocks))
    for i in range(numBlocks):
        R0 = input[(i*8):(i*8)+4][::-1]
        L0 = input[(i*8)+4:(i*8)+8][::-1]
        Li, Ri = L0, R0
        for i in range(GOST_ROUNDS):
            Li, Ri = gostRound(Li, Ri, i, GOST_DECRYPT)
        #print('L32: {}\t R32: {}'.format(Ri, Li))
        processedText = processedText + Ri + Li
    return pkcs7Unpadding(processedText)


# Main Driver
if __name__ == '__main__':
    tprint('\nGOST 28147-89\n        > ECB mode <')
    parser = argparse.ArgumentParser(prog='GOST.py',
                                      description='GOST block cipher encrypt/decrypt')
    parser.add_argument('-k', '--key', help='Key file for generating the key space')
    parser.add_argument('-in', '--inputfile', help='input byte buffer from file')
    parser.add_argument('-out', '--outputfile', help='output byte buffer to file')
    parser.add_argument('-encrypt', '--encrypt', default=False, action='store_true')
    parser.add_argument('-decrypt', '--decrypt', default=False, action='store_true')
    args = parser.parse_args()

    print('\n++ GOST 28147-89 - Electronic Codebook Mode(ECB) ++')
     
    if (args.key == None) or (args.inputfile == None) or (args.outputfile == None):
        print('\nUsage: ./gost.py -k key.bin -in|out file.bin -enc|-dec\n')
        exit(0)
    else:
        with open(args.key, 'rb') as fr:
            key_space = getKeys(fr.read()) 

    for i in range(len(key_space)):
        print('K{}: {}'.format(i, bytes.hex(key_space[i])))
    
    ''' 
    with open('./filename.bin', 'wb') as f:
        f.write(getRandomKey())
    exit(0)
    ''' 
    print()
    if (args.encrypt):
        with open(args.inputfile, 'rb') as fr, open(args.outputfile, 'wb') as fw:
            cipher = dataEncrypt(fr.read())
            fw.write(cipher)
        #print('cipher+padding: {}, len: {} bytes'.format(cipher, len(cipher)))
    elif (args.decrypt):
        with open(args.inputfile, 'rb') as fr, open(args.outputfile, 'wb') as fw:
            plain = dataDecrypt(fr.read())
            fw.write(plain)
        #print('buffer: {}, len: {} bytes'.format(plain, len(plain)))
