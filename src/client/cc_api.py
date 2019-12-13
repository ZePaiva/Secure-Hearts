# encoding libs
import base64

#crypto libs
from PyKCS11 import *

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)
from cryptography.x509 import *
from cryptography.x509.oid import NameOID

# miscellanious libs
from bullet import Password
from enum import Enum

# miscellanious
lib='/usr/local/lib/libpteidpkcs11.so'
red='\033[91m'
normal='\033[0m'

# PT Citizen Card API
class CC_API(object):
    def __init__(self):
        self.pkcs11=PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)
        self.slot=self.pkcs11.getSlotList()[0]
        self.session=self.pkcs11.openSession(self.slot)

    # ask user pin
    def ask_pin(self):
        while True:
            cli=Password(prompt="Ctizen Card Pin: ", hidden="*")
            usr_pin=cli.launch()
            try:
                self.session.login(usr_pin)
                return None
            except PyKCS11Error:
                print(red+'FAILURE... Bad Pin'+normal)
            except Exception as e:
                print(e)

    # sign data with 
    def sign_data(self, data):
        try:
            session=self.pkcs11.openSession(self.slot)
            self.ask_pin(session)
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
    def verify_data(self, signature, data):
        try:
            session=self.pkcs11.openSession(self.slot)
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
    def encrypt_with_cc(self, message):
        session=pkcs11.openSession(self.slot)
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
    def decrypt_with_cc(self, ciphertext):
        session=pkcs11.openSession(self.slot)
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

    # get certificate from citizen card
    def get_citizen_card_info(self):
        session = self.pkcs11.openSession( self.slot )
        private_key = session.findObjects(
            [(CKA_CLASS, CKO_PRIVATE_KEY),
             (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')]
        )[0]
        cert = session.findObjects(
            [(CKA_CLASS, CKO_CERTIFICATE)]
        )[0]
        cert_der = bytes(session.getAttributeValue( cert, [CKA_VALUE], True )[0])
        session.closeSession()
        certificate = x509.load_der_x509_certificate(
            cert_der, 
            default_backend()
        )
        commonname = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        serialnumber = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        return {
            "name": commonname,
            "serialnumber": serialnumber
        }

cc=CC_API()
cc.ask_pin()
