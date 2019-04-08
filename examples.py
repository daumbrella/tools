# -*- coding: utf-8 -*-
"""
Created on Thu Apr  4 15:51:37 2019

@author: yayao
"""
import pcap_utils
import aes_utils

#test pcap utils
pcap_utils.traverse_pcap("jd_control.pcap","udp")

#test aes length = 16

#when the key, plain, and iv is bytes  
plain3=b"hello world"
key=b"keyskeyskeyskeys"
iv=b"iviviviviviviviv"
cipher3=aes_utils.encrypt(plain3,key,iv)
print(cipher3)
print(aes_utils.decrypt(cipher3,key,iv))

# when the key, plain, and iv is string , encode is required, results are same as bytes
plain1="hello world"
key="keyskeyskeyskeys"
iv="iviviviviviviviv"
cipher1=aes_utils.encrypt(plain1.encode('utf-8'),key.encode('utf-8'),iv.encode('utf-8'))
print(cipher1)
print(aes_utils.decrypt(cipher1,key.encode('utf-8'),iv.encode('utf-8')))

#when the key, plian, and iv is hex string, bytearray.fromhex()
plain2=b"hello world"
key=bytearray.fromhex("0fb437ba8ff4f79344ca6bfe7e8c7e6e")
iv=bytearray.fromhex("0fb437ba8ff4f79344ca6bfe7e8c7e6e")
cipher2=aes_utils.encrypt(plain2,key,iv)
print(cipher2)
print(aes_utils.decrypt(cipher2,key,iv))

