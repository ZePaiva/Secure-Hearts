from lib import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import *
import os
import base64

import logging

client_logger=logging.getLogger('SECURITY')
logging.basicConfig(filename='log/client_'+str(int(time.time()))+'.logs',
                            filemode='a',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)

class CryptographyClient(object):
    def __init__(self, cc_api):
        self.cc_api=cc_api

    def get_hashing(self, hashing):
        hash_alg={
            'MD5':hashes.MD5(),
            '128':hashes.SHA128(),
            '256':hashes.SHA256(),
        }
        return hash_alg[hashing]

    def 

