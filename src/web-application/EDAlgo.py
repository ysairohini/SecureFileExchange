import binascii
import os
import time
import base64
import hashlib
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES
from secretsharing import PlaintextToHexSecretSharer
from secretsharing import SecretSharer

# BS = 16
# pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()
# unpad = lambda s: s[:-ord(s[len(s)-1:])]
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[:-ord(s[len(s)-1:])]

def iv():
    return chr(0) * 16

# class AESCipher(object):
#     global iv
#     def __init__(self, key):
#         self.key = key
#         print(key)

#     def encrypt(self, message):
#         message = message.encode()
#         raw = pad(message)
#         cipherE = AES.new(self.key, AES.MODE_CFB)
#         enc = cipherE.encrypt(raw)
#         return base64.b64encode(enc).decode()

#     def decrypt(self, enc):
#         cipher = AES.new(self.key, AES.MODE_CFB)
#         dec = cipher.decrypt(enc)
#         print(dec)
#         return unpad(dec).decode()

class AESCipher(object):
    
    global iv
    def __init__(self, key):
        self.key = hashlib.sha256(b'16-character key').digest()
        print(key)

    def encrypt(self,raw):
        BS = AES.block_size
        pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

        raw = base64.b64encode(pad(raw).encode('utf8'))
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key= self.key, mode= AES.MODE_CFB,iv= iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self,enc):
        unpad = lambda s: s[:-ord(s[-1:])]

        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))