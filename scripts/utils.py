from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.ciphers import Cipher, algorithms, modes

import sys
import os

def main():
    print('Python cryptography utils functions:')
    print('====================================')
    print('Asymmetric ciphers utils:')
    print('++++++++++++++++++++++++++++++++++++')
    print(' -> load_key(path_to_key, password=None, private=True) => bytes')
    print('    * path_to_key -> string')
    print('    * password    -> string')
    print('    * private     -> booleans')
    print('------------------------------------')
    print(' -> sign(message, priv_key, prehash=False) => bytes')
    print('    * message  -> bytes')
    print('    * priv_key -> bytes')
    print('------------------------------------')
    print(' -> verify(signature, message, pub_key) => boolean')
    print('    * signature -> bytes')
    print('    * message   -> bytes')
    print('    * pub_key   -> bytes')
    print('------------------------------------')
    print(' -> asym_encrypt(message, pub_key) => bytes')
    print('    * message   -> bytes')
    print('    * pub_key   -> bytes')
    print('------------------------------------')
    print(' -> asym_decrypt(cipher, prv_key) => bytes')
    print('    * cipher    -> bytes')
    print('    * prv_key   -> bytes')
    print('====================================')
    print('Symmetric ciphers utils:')
    print('++++++++++++++++++++++++++++++++++++')
    print(' -> sym_encrypt(message, sec_key) => bytes')
    print('    * message   -> bytes')
    print('    * sec_key   -> bytes')
    print('------------------------------------')
    print(' -> sym_decrypt(message, sec_key) => bytes')
    print('    * coded_msg -> bytes')
    print('    * sec_key   -> bytes')
    print('------------------------------------')

def load_key(path_to_key, password=None, private=True):
    try:
        with open(path_to_key, 'rb') as kf:
            if private:
                key=serialization.load_pem_private_key(
                    kf.read(),
                    bytes(password, 'utf-8'),
                    default_backend()
                )
            

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
    except cryptography.exceptions.InvalidSignature as e:
        print(e)
        return False
    except Exception as e:
        print(e)
        return e

def asym_encrypt(message, pub_key):
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

def asym_decrypt(cipher, prv_key):
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

def sym_encript(message, sec_key):
    try: 
        iv = os.urandom(
            algorithms.AES.block_size // 8
        )
        cipher=Cipher(
            algorithms.AES(sec_key),
            modes.CBC(iv),
            default_backend()
        )
        encryptor=cipher.encryptor()
        padder=padding.PKCS7(algorithms.AES.block_size).padder()
        coded_msg=encryptor.update(padder.update(message)+padder.finalize())
        return coded_msg
    except Exception as e:
        print(e)
        return e

def sym_decrypt(coded_msg, sec_key)
    try:
        iv = os.urandom(
            algorithms.AES.block_size // 8
        )
        cipher=Cipher(
            algorithms.AES(sec_key),
            modes.CBC(iv),
            default_backend()
        )
        decryptor=cipher.decryptor()
        decryptor.update(coded_msg)+decryptor.finalize()
    except Exception as e:
        print (e)
        return e

if __name__=='__main__':
    main()
