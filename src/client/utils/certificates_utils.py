# utils
import os
import base64
import datetime

# crypto modules
from cryptography import x509
from cryptography.x509 import *
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from OpenSSL import crypto
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext, X509StoreFlags, X509StoreContextError
######## CERTIFICATES STUFF ########
# args:
#   -> name: string
# return:
#   -> RSA private bytes
#   -> Certificate public bytes
def generate_certificate(name):
    priv_key = rsa.generate_private_key(
        backend=default_backend(), 
        public_exponent=65537, 
        key_size=2048)
    public_key = priv_key.public_key()
    cert_private = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM, 
        format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My Company'),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])
    cert_private = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName('localhost')]),
        critical=False,
    ).sign(
        priv_key, 
        hashes.SHA256(), 
        default_backend()
    )

    return cert_private, cert_private.public_bytes(serialization.Encoding.PEM)

# args:
#   -> cert: certificate
#   -> type: string      (optional)
# return:
#   -> bytes
def serialize_cert(cert, c_type='PEM'):
    if not cert:
        return None
    if c_type=='PEM':
        return base64.b64encode(
            crypto.dump_certificate(
                crypto.FILETYPE_PEM, 
                cert
            )
        ).decode('utf-8')
    else:
        return base64.b64encode(
            crypto.dump_certificate(
                crypto.FILETYPE_ASN1, 
                cert
            )
        ).decode('utf-8')

# args:
#   -> cert: bytes
#   -> type: string      (optional)
# return:
#   -> certificate
def deserialize_cert(cert, c_type='PEM'):
    if not cert:
        return None
    if c_type=='PEM':
        return crypto.load_certificate(
            crypto.FILETYPE_PEM,
            base64.b64decode(
                cert.encode('utf-8')
            )
        )
    else:
        return crypto.load_certificate(
            crypto.FILETYPE_ASN1,
            base64.b64decode(
                cert.encode('utf-8')
            )
        )

# args:
#   -> cert: x509 PEM Certificate
#   -> type: string      (optional)
# returns:
#   -> string
def get_certificate_id(cert, c_type='PEM'):
    if c_type=='PEM':
        certificate=load_pem_x509_certificate(
            cert,
            default_backend()
        )
    else:
        certificate=load_der_x509_certificate(
            cert,
            default_backend()
        )
    id=certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return id

# args:
#   -> cert: x509 PEM Certificate
#   -> type: string      (optional)
# returns:
#   -> string
def get_certificate_issuer(cert, c_type='PEM'):
    if c_type=='PEM':
        certificate=load_pem_x509_certificate(
            cert,
            default_backend()
        )
    else:
        certificate=load_der_x509_certificate(
            cert,
            default_backend()
        )
    id=certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    return id

def get_cert_status_ocsp(cert, c_type='PEM'):
    if c_type=='PEM':
        certificate=load_pem_x509_certificate(
            cert,
            default_backend()
        )
    else:
        certificate=load_der_x509_certificate(
            cert,
            default_backend()
        )
    extension=certificate.extensions.get_attributes_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)[0].value
    print(extension) # assume it has already http imbued
    # TBD

# args:
#   -> dir: string
# returns:
#   -> dict of type:
#           {
#               <subject_id>: {
#                   'cert': <certificate>,
#                   'path': <certificate_path>,
#                   'type': <certificate_type>
#               }
#           }
def import_certficates(dir):
    cert_files=[file for file in os.listdir(dir)]
    certs={}

    for file in cert_files:
        cert=None
        path=os.path.join(dir, cert)
        c_type='PEM'
        # try to open PEM file type
        try:
            f=open(path, 'rb')
            cert=deserialize_cert(f.read())
            f.close()
        except crypto.Error as e:
            f.close()
            c_type='DER'
        # ty to open DER file type, if failed just ignores file
        if not cert:
            try:
                f=open(path, 'rb')
                cert=deserialize_cert(f.read(), c_type='DER')
                f.close()
            except crypto.Error as e:
                f.close()
                print('Error on file %s, please delete it' % path)
                continue
        id=get_certificate_id(cert, c_type=c_type)
        if id not in certs:
            certs[id]={'cert': cert, 'path': path, 'type': c_type}
        return certs

# args:
#   -> root_certificates: list of X509Certificates
#   -> trusted_certificates: list of X509Certificates
#   -> crl_list: list of CRL 
# returns:
#   -> X509Store
def load_KeyStore(root_certificates, trusted_certificates, crl_list):
    try:
        store=X509Store()
        i=0
        for root in root_certificates:
            store.add_cert(root)
            i+=1
        i=0
        for trusted in trusted_certificates:
            store.add_cert(trusted)
            i+=1
        i=0
        for crl in crl_list:
            store.add_crl(crl)
            i+=1
        store.set_flags(X509StoreFlags.CRL_CHECK | X509StoreFlags.IGNORE_CRITICAL)
    except X509StoreContext:
        return None
    else:
        return store

# returns:
#   -> list of X509Certificates
#   -> list of X509Certificates
#   -> list of X509CRL
def load_certificates():
    root_certificates=[] 
    trusted_certificates=[]
    crl_list=[]
    dirname=["CCCerts/", "CCCRL/"]
    # load certificates
    for filename in os.listdir(dirname[0]):
        try:
            cert_info = open(dirname[0]+filename, 'rb').read()
        except IOError:
            exit(10)
        else:
            if ".cer" in filename:
                try:
                    if "0012" in filename or "0013" in filename or "0015" in filename:
                        certAuth=load_certificate(FILETYPE_PEM, cert_info)
                    elif "Raiz" in filename:
                        root=load_certificate(FILETYPE_ASN1,cert_info)
                    else:
                        certAuth=load_certificate(FILETYPE_ASN1, cert_info)
                except Exception as e:
                    exit(10)
                else:
                    trusted_certificates=trusted_certificates+[certAuth]
            elif ".crt" in filename:
                try:
                    if "ca_ecc" in filename:
                        root=load_certificate(FILETYPE_PEM, cert_info)
                    elif "-self" in filename:
                        root=load_certificate(FILETYPE_PEM, cert_info)
                    else:
                        root=load_certificate(FILETYPE_ASN1, cert_info)
                except :
                    exit(10)
                else:
                    root_certificates=root_certificates+[root]
    # load certificate revocation lists
    for filename in os.listdir(dirname[1]):
        try:
            crl_info=open(dirname[1]+"/"+filename,'rb').read()
        except IOError:
            exit(11)
        else:
            if ".crl" in filename:
                crls=load_crl(FILETYPE_ASN1, crl_info)
        crl_list=crl_list+[crls]
    return root_certificates, trusted_certificates, crl_list

# args:
#   -> cert: x509 PEM Certificate
#   -> type: string      (optional)
# returns:
#   -> string
def check_revoked_certificate(cert, c_type='PEM'):
    issuer=get_certificate_issuer(cert, c_type=c_type)
    # TBD


######## CRL STUFF ########

