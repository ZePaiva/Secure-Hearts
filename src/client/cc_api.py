# encoding libs
import base64

# logging stuff
import logging

#crypto libs
from PyKCS11 import *
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

    # ask user pin
    def ask_pin(self):
        while True:
            session=self.pkcs11.openSession(self.slot)
            cli=Password(prompt="Ctizen Card Pin: ", hidden="*")
            usr_pin=cli.launch()
            try:
                session.login(usr_pin)
                session.logout()
                session.closeSession()
                return usr_pin
            except PyKCS11Error:
                print(red+'FAILURE... Bad Pin'+normal)
            except Exception as e:
                print(red+e+normal)
        return None

    # get public key from cc:
    def get_pubKey(self, pin=None):
        try:
            session=self.pkcs11.openSession(self.slot)
            session.login(pin)
            pb_key=session.findObjects(
                [
                    (CKA_CLASS, CKO_PUBLIC_KEY),
                    (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            pub_key_DER=session.getAttributeValue(
                pb_key, 
                [CKA_VALUE],
                True
            )[0]
            public_key=load_der_public_key(
                bytes(pub_key_DER),
                default_backend()
            )
            session.logout()
            session.closeSession()
        except Exception as e:
            session.logout()
            session.closeSession()
            print(e)
            return None
        return public_key

    # get certificates
    def get_all_certs(self, pin=None):
        certs=[]
        session=self.pkcs11.openSession(self.slot)
        try:
            session.login(pin)
            cc_certs_obj=session.findObjects(
                [
                    (CKA_CLASS, CKO_CERTIFICATE)
                ]
            )
            for cert_obj in cc_certs_obj:
                cert_val=session.getAttributeValue(
                    cert_obj,
                    [CKA_VALUE],
                    True
                )[0]
                cert=load_der_x509_certificate(
                    bytes(cert_val),
                    default_backend()
                )
                certs+=[cert]
            session.logout()
            session.closeSession()
        except Exception as e:
            session.logout()
            session.closeSession()
            print(red+e+normal)
            return None
        return certs

    # sign data with citizen card 
    def cc_sign(self, data, pin=None, cipher_method=Mechanism(CKM_SHA1_RSA_PKCS)):
        ession=self.pkcs11.openSession(self.slot)
        try:
            session.login(pin)
            prv_key=session.findObjects(
                [
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            signature=bytes(session.sign(prv_key, data, cipher_method))
            session.logout()
            session.closeSession()
        except Exception as e:
            session.logout()
            session.closeSession()
            print(e)
            return e
        return signature

    # get certificate from citizen card
    def get_citizen_card_info(self, pin=None):
        session=self.pkcs11.openSession(self.slot)
        private_key=session.findObjects(
            [(CKA_CLASS, CKO_PRIVATE_KEY),
             (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')]
        )[0]
        cert=session.findObjects(
            [(CKA_CLASS, CKO_CERTIFICATE)]
        )[0]
        cert_der=bytes(session.getAttributeValue( cert, [CKA_VALUE], True )[0])
        certificate = load_der_x509_certificate(
            cert_der, 
            default_backend()
        )
        commonname = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        serialnumber = certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        return {
            "name": commonname,
            "serialnumber": serialnumber
        }

#API=CC_API()
#pin=API.ask_pin()
#print(pin)
#print(API.get_citizen_card_info())
