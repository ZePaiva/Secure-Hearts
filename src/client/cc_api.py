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
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext,\
    X509StoreFlags, X509StoreContextError

# miscellanious libs
from bullet import Password

#utils
import os
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
        self.cached=False
        roots, trusted, crl= self.load_certificates()
        self.cc_KS=self.load_KeyStore(roots, trusted, crl)

    # ask user pin
    def ask_pin(self, to_cache=False):
        if to_cache:
            self.cached=True
        while True:
            session=self.pkcs11.openSession(self.slot)
            cli=Password(prompt="Citizen Card Pin: ", hidden="*")
            usr_pin=cli.launch()
            try:
                session.login(usr_pin)
                if not to_cache:
                    session.logout()
                    session.closeSession()
                return usr_pin, session
            except PyKCS11Error:
                print(red+'FAILURE... Bad Pin'+normal)
            except Exception as e:
                print(red+e+normal)
        return None

    # get public key from cc:
    def get_pubKey(self, session=None, pin=None):
        if not session:
            session=self.pkcs11.openSession(self.slot)
            if pin:
                session.login(pin)
        try:
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
            if not self.cached:
                session.logout()
                session.closeSession()
        except Exception as e:
            if not self.cached:
                session.logout()
                session.closeSession()
            print(e)
            return None
        return public_key

    # get certificate from public key
    def get_pubKey_cert(self, session=None):
        if not session:
            session=self.pkcs11.openSession(self.slot)
        try:
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
                cert_issuer = cert.issuer
                issuer=cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
                if 'EC de Autenticação do Cartão de Cidadão 00' in issuer:
                    return cert
            if not self.cached:
                session.logout()
                session.closeSession()
        except Exception as e:
            if not self.cached:
                session.logout()
                session.closeSession()
            print(e)
            return None
        return None

    # load certificates from local dir
    def load_certificates(self):
        # root => issuer== commom name 
        rootCerts = ()
        trustedCerts = ()
        crlList = ()
        dirname = ["CCCerts/", "CCCRL/"]
        # load certificates
        for filename in os.listdir(dirname[0]):
            try:
                cert_info = open(dirname[0] + filename, 'rb').read()
            except IOError:
                exit(10)
            else:
                if ".cer" in filename:
                    try:
                        if "0012" in filename or "0013" in filename or "0015" in filename:
                            certAuth = load_certificate(FILETYPE_PEM, cert_info)
                        elif "Raiz" in filename:
                            root = load_certificate(FILETYPE_ASN1,cert_info)
                        else:
                            certAuth = load_certificate(FILETYPE_ASN1, cert_info)
                    except Exception as e:
                        exit(10)
                    else:
                        trustedCerts = trustedCerts + (certAuth,)
                elif ".crt" in filename:
                    try:
                        if "ca_ecc" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        elif "-self" in filename:
                            root = load_certificate(FILETYPE_PEM, cert_info)
                        else:
                            root = load_certificate(FILETYPE_ASN1, cert_info)
                    except :
                        exit(10)
                    else:
                        rootCerts = rootCerts + (root,)
        # load certificate revocation lists
        for filename in os.listdir(dirname[1]):
            try:
                crl_info = open(dirname[1] + "/" + filename, 'rb').read()
            except IOError:
                exit(11)
            else:
                if ".crl" in filename:
                    crls = load_crl(FILETYPE_ASN1, crl_info)
            crlList = crlList + (crls,)
        return rootCerts, trustedCerts, crlList

    def load_KeyStore(self, rootCerts, trustedCerts, crlList):
        try:
            store = X509Store()
            i = 0
            for root in rootCerts:
                store.add_cert(root)
                i += 1
            i = 0
            for trusted in trustedCerts:
                store.add_cert(trusted)
                i += 1

            i = 0
            for crl in crlList:
                store.add_crl(crl)
                i += 1
            store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
        except X509StoreContext:

            return None
        else:
            return store

    # get certificates
    def get_all_certs(self, session=None):
        certs=[]
        if not session:
            session=self.pkcs11.openSession(self.slot)
        try:
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
        except Exception as e:
            if not self.cached:
                session.logout()
                session.closeSession()
            print(red+e+normal)
            return None
        return certs

    # sign data with citizen card 
    # ERROR: should be mechanism CKM_SHA256_RSA_PKCS_PSS but it throws error
    def cc_sign(self, data, pin=None, session=None, cipher_method=Mechanism(CKM_SHA256_RSA_PKCS)):
        if not session:
            session=self.pkcs11.openSession(self.slot)
            if pin:
                session.login(pin)
        try:
            prv_key=session.findObjects(
                [
                    (CKA_CLASS, CKO_PRIVATE_KEY),
                    (CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
                ]
            )[0]
            signature=bytes(session.sign(prv_key, data, cipher_method))
            if not self.cached:
                session.logout()
                session.closeSession()
        except Exception as e:
            if not self.cached:
                session.logout()
                session.closeSession()
            print(e)
            return e
        return signature

    # get certificate from citizen card
    def get_citizen_card_info(self, session=None, pin=None):
        if not session:
            session=self.pkcs11.openSession(self.slot)
            if pin:
                session.login(pin)
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
        if not self.cached:
            session.logout()
            session.closeSession()

#API=CC_API()
#pin=API.ask_pin()
#print(pin)
#print(API.get_pubKey_cert())
