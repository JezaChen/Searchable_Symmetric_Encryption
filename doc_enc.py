# coding=utf-8
import os
import re
import hashlib
import random
import math
import array
import string
from Crypto.Cipher import AES
from Crypto import Random
import scanner


def enc_doc(index, k):
    with open('plain_text/' + str(index) + '.txt', encoding='UTF-8') as src:
        with open('cipher_text/' + str(index) + '.enc', 'wb') as dst:
            iv = os.urandom(AES.block_size)
            cryptor = AES.new(k, AES.MODE_CFB, iv)
            cipher = cryptor.encrypt(bytes(src.read(), encoding='UTF-8'))
            dst.write(iv + cipher)


def dec_doc(index, k):
    with open('cipher_text/' + str(index) + '.enc', 'rb') as src:
        with open(str(index) + '.dec', 'w', encoding='UTF-8') as dst:
            cipher = src.read()
            iv = cipher[:AES.block_size]
            cipher = cipher[AES.block_size:]
            cryptor = AES.new(k, AES.MODE_CFB, iv)
            plain = cryptor.decrypt(cipher)
            dst.write(plain.decode('UTF-8'))


if __name__ == '__main__':
    key = Random.new().read(16)
    enc_doc(0, key)
    dec_doc(0, key)
