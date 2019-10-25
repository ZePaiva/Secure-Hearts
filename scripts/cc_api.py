from PyKCS11 import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)

from bullet import Password

lib='/usr/local/lib/libpteidpkcs11.so'
pteidlib='/usr/local/lib/libpteidlib.so'

pkcs11=PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slot=pkcs11.getSlotList()[0]
red='\033[91m'
normal='\033[0m'

# ask user pin
def ask_pin(session):
    while True:
        cli=Password(prompt="Ctizen Card Pin: ", hidden="*")
        usr_pin=cli.launch()
        try:
            session.login(usr_pin)
            return None
        except PyKCS11Error:
            print(red+'FAILURE... Bad Pin'+normal)
        except Exception as e:
            print(e)

# sign data with 
def sign_data(data):
    try:
        session=pkcs11.openSession(slot)
        ask_pin(session)
        prv_key=session.findObjects(
            [
                (CKA_CLASS, CKO_PRIVATE_KEY),
                (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
            ]
        )[0]
        signature=bytes(session.sign(prv_key, data, Mechanism( CKM_SHA1_RSA_PKCS)))
        session.logout()
        session.closeSession()
        return signature
    except Exception as e:
        print(e)
        return e

# verify data and signature
def verify_data(signature, data):
    try:
        session=pkcs11.openSession(slot)
        ask_pin(session)
        pub_key_handle=session.findObjects(
            [
                (CKA_CLASS, CKO_PUBLIC_KEY),
                (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
            ]
        )[0]
        pub_key_DER=session.getAttributeValue(
            pub_key_handle, 
            [CKA_VALUE],
            True
        )[0]
        session.logout()
        session.closeSession()
        public_key=load_der_public_key(
            bytes(pub_key_DER),
            default_backend()
        )
        try:
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA1())
            return True
        except Exception as e:
            print(e)
            return False
    except Exception as e:
        print(e)
        return e

# encrypt data
# MIGHT NOT BE IMPLEMENTED BY CC MAKER
def encrypt_with_cc(message):
    session=pkcs11.openSession(slot)
    ask_pin(session)
    try:
        public_key=session.findObjects(
            [(CKA_CLASS, CKO_PUBLIC_KEY)]
        )[0]
        encrypted_msg=session.encrypt(public_key, message)
    except PyKCS11Error:
        print(red+'Function not implemented'+normal)
        session.logout()
        session.closeSession()
        return None
    session.logout()
    session.closeSession()
    return encrypted_msg

# decrypt data
# MIGHT NOT BE IMPLEMENTED BY CC MAKER
def decrypt_with_cc(ciphertext):
    session=pkcs11.openSession(slot)
    ask_pin(session)
    try:
        private_key=session.findObjects(
            [(CKA_CLASS, CKO_PRIVATE_KEY)]
        )[0]
        message=session.decrypt(private_key, ciphertext)
    except PyKCS11Error:
        print(red+'Function not implemented'+normal)
        session.logout()
        session.closeSession()
        return None
    session.logout()
    session.closeSession()
    return message

#cipher=encrypt_with_cc(b'ola')
#print(decrypt_with_cc(cipher))

#sig=sign_data(b'ola')
#print(verify_data(sig, b'ola'))
