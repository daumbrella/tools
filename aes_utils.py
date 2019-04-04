# -*- coding:utf-8 -*-
 
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
 
 
def bin_encrypt(text, key ,iv):
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    length = 16 # 16 or 24 or 32
    count = len(text)
    if count < length:
        add = (length - count)
        text = text + ('\0' * add).encode('utf-8')
    elif count > length:
        add = (length - (count % length))
        text = text + ('\0' * add).encode('utf-8')
    ciphertext = cryptor.encrypt(text)
    return b2a_hex(ciphertext)

def bin_decrypt(text, key ,iv):
    text = text.encode('utf-8')
    if type(key).__name__ == 'str':
        key = key.encode('utf-8')
        iv = iv.encode('utf-8')
    cryptor = AES.new(key, AES.MODE_CBC, iv)
    plain_text = cryptor.decrypt(a2b_hex(text)) #返回的是二进制格式
    return plain_text
