from PyKCS11 import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)

lib='/usr/local/lib/libpteidpkcs11.so'
pteidlib='/usr/local/lib/libpteidlib.so'

pkcs11=PyKCS11.PyKCS11Lib()
pkcs11.load(lib)
slot=pkcs11.getSlotList()[0]

# sign data with 
def sign_data(data):
    try:
        if b'CARTAO DE CIDADAO' in pkcs11.getTokenInfo(slot).label:
            session=pkcs11.openSession(slot)
            prv_key=session.findObjects(
                [
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            signature=bytes(session.sign(prv_key, data, Mechanism( CKM_SHA1_RSA_PKCS)))
            session.closeSession()
        return signature
    except Exception as e:
        print(e)
        return e
# verify data and signature
def verify_data(signature, data):
    try:
        for slot in slots:
            session=pkcs11.openSession(slot)
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


sig=sign_data(b'ola')
print(verify_data(sig, b'ola'))
