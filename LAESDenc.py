import binascii
import math
import random
import numpy as np
import time
import os
from backports.pbkdf2 import pbkdf2_hmac


def leftRotate(n, d):
 
    return (((n << d)|(n >> (4 - d))) & 0xF)


def encrypt(block, key):
    keyLen = len(key)
    sqrtKeyLen = int(math.sqrt(keyLen))

    if ((((sqrtKeyLen)**2) == keyLen) and (keyLen%2==0)):

        block=list(block)
        key=list(key)

        sbox = [
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01,   0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
                0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
                0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
                0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
                0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
                0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
                0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
                0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
                0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
                0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
                0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
                0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
                0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
                0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
                0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
            ]
           
        sbox = np.array(sbox).reshape(16, 16).tolist()

        random.seed(int(key[0],16))
        sboxShift=int((10*random.random())%(1+10*random.random()))
        print("Sshift")
        print(sboxShift)
        for i in range(16):
                tmp = sbox[i]
                for j in range(sboxShift+int(10*random.random())):
                    elem = tmp[0]
                    for k in range(15):
                        tmp[k] = tmp[k+1]
                    tmp[15] = elem
                sbox[i] = tmp


        for round in range(10):

            for i in range(keyLen):
                c1 = int(block[i], 16)
                c2 = int(key[i], 16)
                c1=c1^c2
                block[i]=str(hex(c1))[2]

                

            for i in range(0, len(block), 2):
                c1 = int(block[i], 16)
                c2 = int(block[i+1], 16)
                substitute = str(hex(sbox[c1][c2]))

                if  len(substitute)==3:
                    block[i] = '0'
                    block[i+1] = substitute[2]
                else:
                    block[i] = substitute[2]
                    block[i+1] = substitute[3]

            
            
            block = np.array(block).reshape(sqrtKeyLen, sqrtKeyLen)
            block=block.tolist()

            #Shifting rows
            for i in range(sqrtKeyLen):
                tmp = block[i]
                for j in range(i):
                    elem = tmp[0]
                    for k in range(sqrtKeyLen-1):
                        tmp[k] = tmp[k+1]
                    tmp[sqrtKeyLen-1] = elem
                block[i] = tmp
           
            colMixMat = []
            for i in range (keyLen):
                random.seed(i)
                colMixMat.append(random.sample(range(1,3),1))
            colMixMat = (np.array(colMixMat).reshape(sqrtKeyLen, sqrtKeyLen)).tolist()


            for i in range(sqrtKeyLen):
                for j in range(sqrtKeyLen):
                    tmp=int(block[i][j], 16)
                    tmp=leftRotate(tmp,colMixMat[i][j])
                    block[i][j]=(str(hex(tmp)))[2]            
            
            
            #Round keys
            for i in range(keyLen-1):
                c1 = int(key[i], 16)
                c2 = int(key[i+1], 16)
                c1=c1^c2
                key[i]=str(hex(c1))[2]

            block=[j for i in block for j in i]
        
        block=''.join(block)
        block=bytes(block,'utf-8')
        return block


#startTime=time.time()


salt = binascii.unhexlify('aaef2d3f4d77ac66e9c5a6c3d8f921d1')
passwd = "p@$Sw0rD~1".encode("utf8")
key = pbkdf2_hmac("sha256", passwd, salt, 50000, 16)
key = binascii.hexlify(key)

with open('sample.txt', 'rb') as unenc_file:
    hexdata = binascii.hexlify(unenc_file.read())

unenc_file.close()

print("The unencrypted file is: ")
print(hexdata)


#Add padding
countByte = 0
encryptedFile=b''

while countByte < len(hexdata):
    dataBlock = hexdata[countByte:countByte+len(key)]
    if len(dataBlock) < len(key):
        dataBlock += hexdata[0:(len(key)-len(dataBlock))]
    
    strdata = dataBlock.decode()
    countByte += len(key)
    
    encryptedFile+=encrypt(strdata, key)

print("The encrypted file is: ")
print(encryptedFile)



enc_file = open('sample.txt', 'wb')
enc_file.write(binascii.unhexlify(encryptedFile))
enc_file.close()

# print("The time required for encrypting the file using LAESD is :")
# print(time.time()-startTime)