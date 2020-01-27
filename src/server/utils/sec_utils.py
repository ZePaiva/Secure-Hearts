import base64 
import sys 
import os

from OpenSSL import crypto
from cryptography.fernet import Fernet
from cryptography.exceptions import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

######## SELECTORS ########
# args:
#   -> hashing: string
# returns:
#   -> hashes.METHOD
def get_hash_alg(hashing):
    hash_algs={
        'MD5': hashes.MD5(),
        'SHA2': hashes.SHA256(),
        'SHA3': hashes.SHA3_256()
    }
    return hash_algs[hashing]

# args:
#   -> mode: string
#   -> iv  : 16-byte integer
# returns:
#   -> modes.METHOD
def get_sym_mode(mode, iv):
    modes={
        'CBC': modes.CBC(iv),
        'CTR': modes.CTR(iv),
        'OFB': modes.OFB(iv),
        'CFB': modes.CFB(iv),
        'CFB8': modes.CFB8(iv)
    }
    return modes[mode]

# args:
#   -> mode     : string
#   -> hash_alg : hashes.METHOD()
# returns:
#   -> padding.METHOD
def get_padding_mode(mode, hash_alg):
    paddings={
        'OAEP': padding.OAEP(
            mgf=padding.MGF1(algorithm=hash_alg),
            algorithm=hash_alg,
            label=None
        ),
        'PKCS1v15': padding.PKCS1v15(),
        'PSS': padding.PSS(
            mgf=padding.MGF1(algorithm=hash_alg),
            salt_length=padding.PSS.MAX_LENGTH
        )
    }
    return paddings[mode]

# args:
#   -> algorithm: string
#   -> key      : 128 | 192 | 256 bits
# returns:
#   -> algorithms.METHOD
def get_cipher_alg(algorithm, key):
    algs={
        'AES': algorithms.AES(key),
        'CAM': algorithms.Camellia(key)
    }
    return algs[algorithm]

######## GENERATORS ########
# returns:
#   -> RSAPrivateKey
def generate_rsa():
    private_key=rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    return private_key

# args:
#   -> key : bytes
#   -> mode: string
#   -> alg : string
#   -> iv  : 16-byte integer (optional)
# returns:
#   -> SymmetricCipher
def generate_sym_cipher(key, mode, alg, iv=None):
    if not iv:
        iv=os.urandom(16)
    mode=get_sym_mode(mode, iv)
    c_alg = get_cipher_alg(alg, key)
    cipher = Cipher(
        c_alg,
        mode,
        backend=default_backend()
    )
    return cipher, iv

# args:
#   -> passsword: bytes
#   -> length   : integer
#   -> hash_alg : string
#   -> salt     : bytes
# returns:
#   -> bytes
def generate_derived_key(password, hash_alg, salt=('sec_project_4_rec').encode('utf-8')):
    hashing=get_hash_alg(hash_alg)
    info=('handshake').encode('utf-8')
    derivation=PBKDF2HMAC(
        algorithm=hashing,
        length=length,
        salt=salt,
        info=info,
        backend=default_backend()
    )
    return derivation.derive(password)

# args:
#   -> data_2_digest: bytes
#   -> hash_alg     : string
# returns:
#   -> bytes
def generate_hash_digest(data_2_digest, hash_alg):
    hashing=get_hash_alg(hash_alg)
    digest=hashes.Hash(
        hashing,
        default_backend()
    )
    digest.update(data_2_digest)
    return digest.finalize()

# returns:
#   -> EllipticCurvePrivateKey
def generate_dh():
    key=ec.generate_private_key(
        ec.SECP384R1(),
        default_backend()
    )
    return key

# args:
#   -> private_key  : EllipticCurvePrivateKey
#   -> peer_key     : EllipticCurvePublicKey
#   -> private_salt : bytes
#   -> peer_salt    : bytes
#   -> length       : integer
#   -> hash_alg     : string
#   -> n_derivations: integer
# returns:
#   -> bytes
def generate_key_dh(private_key, peer_key, 
                    private_salt, peer_salt,
                    length, hash_alg, n_derivations):
    secret=private_key.exchange(
        ec.ECDH(),
        peer_key
    )
    key=secret
    for i in range(0, number_of_derivations):
        key=generate_derived_key(
            key,
            length,
            hash_alg,
            private_salt+peer_salt
        )
    return key

# args:
#   -> key     : bytes
#   -> hash_alg: string
#   -> data    : bytes
# returns:
#   -> bytes
def generate_mac(key, data, hash_alg='SHA2'):
    hashing=get_hash_alg(hash_alg)
    mac=hmac.HMAC(key, hashing, backend=default_backend())
    mac.update(data)
    return mac.finalize()

######## FILE OPERS ########
# args:
#   -> path: string
#   -> key : RSAPrivateKey
# returns:
#   -> None
def write_private_key(path, key):
    with open('prv_rsa', 'wb') as file:
        payload=key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        file.write(payload)

# args:
#   -> path: string
# returns:
#   -> RSAPrivateKey
def read_private_key(path):
    with open(path, 'rb') as file:
        payload=serialization.load_pem_private_key(
            file.read(),
            password=None,
            backend=default_backend()
        )
    return payload

# args:
#   -> path: string
#   -> key: RSAPrivateKey
# returns:
#   -> None
def write_public_key(path, key):
    with open(path, 'wb') as file:
        payload=key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        file.write(payload)

# args:
#   -> path: string
# returns:
#   -> RSAPublicKey
def read_public_key(path):
    with open(path, 'rb') as file:
        payload=serialization.load_pem_public_key(
            file.read(),
            backend=default_backend()
        )
    return payload

######## ASYM MECHS ########
# args:
#   -> private_key : RSAPrivateKey
#   -> data        : bytes
#   -> hash_alg    : string (optional)
#   -> padding_mode: string (optional)
# returns:
#   -> 64-byte signature
def sign(private_key, data, hash_alg='SHA1', padding_mode='OAEP'):
    hashing=get_hash_alg(hash_alg)
    padding=get_padding_mode(padding_mode, hashing)
    sign=private_key.sign(data, padding, hashing)
    return sign

# args:
#   -> public_key  : RSAPublicKey
#   -> signature   : 64-byte signature
#   -> data        : bytes
#   -> hash_alg    : string (optional)
#   -> padding_mode: string (optional)
# returns:
#   -> boolean
def verify(public_key, signature, data, hash_alg='SHA2', padding_mode='PSS'):
    hashing=get_hash_alg(hash_alg)
    padding=get_padding_mode(padding_mode, hashing)
    return public_key.verify(signature, data, padding, hashing)
    #return public_key.verify(
    #    signature,
    #    data,
    #    padding.PSS(
    #        mgf=padding.MGF1(hashes.SHA256()),
    #        salt_length=padding.PSS.MAX_LENGTH
    #    ),
    #    hashes.SHA256()
    #)

# args:
#   -> public_key  : RSAPublicKey
#   -> data        : bytes
#   -> hash_alg    : string (optional)
#   -> padding_mode: string (optional)
# returns:
#   -> bytes
def asym_encrypt(public_key, data, hash_alg='SHA1', padding_mode='OAEP'):
    hashing=get_hash_alg(hash_alg)
    padding=get_padding_mode(padding_mode, hashing)
    return public_key.encrypt(data, padding, hashing)

# args:
#   -> private_key : RSAPrivateKey
#   -> data        : bytes
#   -> hash_alg    : string (optional)
#   -> padding_mode: string (optional)
# returns:
#   -> 64-byte signature
def asym_decrypt(private_key, data, hash_alg='SHA1', padding_mode='OAEP'):
    hashing=get_hash_alg(hash_alg)
    padding=get_padding_mode(padding_mode, hashing)
    return public_key.decrypt(data, padding, hashing)

######## SYM MECHS ########
# args:
#   -> data : bytes
#   -> key  : bytes  (optional)
#   -> mode : string (optional)
#   -> alg  : string (optional)
#   -> iv   : 16-byte integer (optional)
# returns:
#   -> bytes
#   -> bytes
#   -> bytes
def sym_encrypt(data, key=None, mode='CBC', alg='AES', iv=None):
    if not key:
        key=os.urandom(32)
    cipher,iv=generate_sym_cipher(key, mode, alg, iv)
    cryptor=cipher.encryptor()
    ciphertext=cryptor.update(data)+encryptor.finalize()
    return key, iv, ciphertext

# args:
#   -> data : bytes
#   -> key  : bytes
#   -> iv   : bytes
#   -> mode : string (optional)
#   -> alg  : string (optional)
# returns:
#   -> bytes
def sym_decrypt(data, key, iv, mode='CBC', alg='AES'):
    cipher,iv=generate_sym_cipher(key, mode, alg, iv)
    cryptor=cipher.decryptor()
    return cryptor.update(data)+encryptor.finalize()

######## MAC ########
# args:
#   -> key      : bytes
#   -> data     : bytes
#   -> signature: bytes
#   -> hash_alg : string
def verify_mac(key, data, signature, hash_alg):
    hashing=get_hash_alg(hash_alg)
    mac = hmac.HMAC(key, hashing, backend=default_backend())
    mac.update(payload)
    try:
        mac.verify(signature)
        return True
    except InvalidSignature:
        return False

######## FERNET ########
# args:
#   -> data: bytes
#   -> key : base64-encoded-32-byte (optional)
# returns:
#   -> bytes
#   -> bytes
def fernet_encrypt(data, key=None):
    if not key:
        key=Fernet.generate_key()
    cipher=Fernet(key)
    return key, cipher.encrypt(data)

# args:
#   -> key : base64-encoded-32-byte
# returns:
#   -> bytes
def fernet_decrypt(key):
    cipher=Fernet(key)
    return cipher.decrypt(data)

######## SERIALIZERS ########
# args:
#   -> key : RSAPublicKey
# returns:
#   -> bytes
def serialize_key(key):
    return base64.b64encode(
        key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode('utf-8')

# args:
#   -> serialized_key : bytes
# returns:
#   -> RSAPublicKey
def deserialize_key(serialized_key):
    return serialization.load_pem_public_key(
        base64.b64decode(
            serialized_key.encode('utf-8')
        ),
        default_backend()
    )

######## GETTERS ########
# args:
#   -> cipher_suite: string of struct:
#       "[HASH_ALG]-[SYM_ALG]-[SYM_MODE]-[CIPHER_PADD]-[SIGN_PADD]-[SIGN_HASH]"
# returns:
#   -> dict of struct:
#       {
#           'hash': [HASH_ALG],
#           'sym': {
#               'key_size' : 128 if [HASH_ALG]=MD5 else 256
#               'algorithm': [SYM_ALG]
#               'mode'     : [SYM_MODE]
#           },
#           'asym': {
#               'cipher_padd':[CIPHER_PADD],
#               'sign': {
#                   'padding': [SIGN_PADD],
#                   'hashing': [SIGN_HASH]
#               }
#           },
#       }
# possible values:
#   [HASH_ALG]    = MD5  | SHA2     | SHA3
#   [SYM_ALG]     = AES  | CAM      | FER
#   [SYM_MODE]    = CBC  | CTR      | OFB  | CFB | CFB8 
#   [CIPHER_PADD] = OAEP | PKCS1v15 | PSS
#   [SIGN_PADD]   = OAEP | PKCS1v15 | PSS
#   [SIGN_HASH]   = MD5  | SHA2     | SHA3
def get_cipher_methods(cipher_suite):
    methods=cipher_suite.split('-')
    key=128 if methods[0]=='MD5' else 256
    cipher_methods={
        'hash': methods[0],
        'sym': {
            'key_size': key,
            'algorithm': methods[1],
            'mode': methods[2]
        },
        'asym': {
            'cipher_padding': methods[3],
            'sign': {
                'padding': methods[4],
                'hashing': methods[5]
            }
        }
    }
    return cipher_methods
