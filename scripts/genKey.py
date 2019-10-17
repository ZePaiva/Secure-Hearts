from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import sys

if len(sys.argv)!=3:
    print('Usage: python genKey.py [size] [pwd]')
    exit(1)

size=sys.argv[1]
pwd=sys.argv[2]

# generate private key
prv_key = rsa.generate_private_key(65537, int(size), default_backend())

# generate public key
pub_key = prv_key.public_key()

# encode private key to store in file
prv_encoding = prv_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.BestAvailableEncryption(
        bytes(
            pwd,
            'utf-8'
        )
    )
)

with open('prv_key.rsa', 'wb') as prv_f:
    prv_f.write(prv_encoding)


# encode public key to store in file
pub_encoding=pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
)

with open('pub_key.rsa', 'wb') as pub_f:
    pub_f.write(pub_encoding)
