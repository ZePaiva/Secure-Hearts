from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


import sys

def main():
    print('Python cryptography utils functions:')
    print('====================================')
    print(' -> sign(message, priv_key, prehash=False) => bytes')
    print('    * message  -> bytes')
    print('    * priv_key -> bytes')
    print('====================================')
    print(' -> verify(signature, message, pub_key) => boolean')
    print('    * signature -> bytes')
    print('    * message   -> bytes')
    print('    * pub_key   -> bytes')
    print('====================================')
    print(' -> encrypt(message, pub_key) => bytes')
    print('    * message   -> bytes')
    print('    * pub_key   -> bytes')
    print('====================================')
    print(' -> decrypt(cipher, prv_key) => bytes')
    print('    * cipher    -> bytes')
    print('    * prv_key   -> bytes')


def sign(message, priv_key):
    signature=None
    try:
        signature=priv_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except Exception as e:
        print(e)
        return e

def verify(signature, message, pub_key):
    try:
        pub_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except cryptography.exceptions.InvalidSignature:
        return False

def encrypt(message, pub_key):
    ciphertext=None
    try:
        ciphertext=pub_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    except Exception as e:
        print(e)
        return e

def decrypt(cipher, prv_key):
    text=None
    try:
        text=prv_key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return text
    except Exception as e:
        print(e)
        return e

