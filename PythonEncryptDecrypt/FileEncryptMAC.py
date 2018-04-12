#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Apr 12 10:33:48 2018

@author: winn
"""
import os, sys, io, json, base64
from cryptography.hazmat.primitives import padding, serialization, hashes, asymmetric, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from array import array


def MyencryptMAC(message, EncKey, HMACKey):
    if(len(encKey) != 32 or len(HMACKey) != 32):
        try:
                raise Exception('ValueError')
            except Exception as error:
                print ("Encryption Key Length:", len(encKey), "bytes")
                print ("HMAC Key Length:", len(hMacKey), "bytes")
                print ("The key(s) entered is not 32 byte.")
                sys.exit(0)    
    
    
def MyfileEncryptMAC(filepath):


def MyRSAEncrypt(filepath, RSA_Publickey_filepath)    