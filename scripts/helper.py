import json
import base64
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import (
    padding, rsa, utils
)


from PyKCS11 import *
HOST = '0.0.0.0'  # The server's hostname or IP address
PORT = 8000        # The port used by the server

pkcs11 = PyKCS11Lib()
pkcs11.load('/usr/local/lib/libpteidpkcs11.so')

slots = pkcs11.getSlotList()

sym_key = None

def sign_with_symetric_key(key, data):
    h = hmac.HMAC(
        key, 
        hashes.SHA256(), 
        backend=default_backend()
    )
    h.update(data)
    signature = base64.b64encode(h.finalize())
    print('signature',signature)
    return signature

def encrypt_with_symetric_key(datain,key):
    data = json.dumps(
        datain,
        ensure_ascii=False,
        separators=(',',':')).encode('utf-8')
    print('before encrypt',data)
    iv=b"k"*16
    try:
        encryptor = Cipher(
            algorithms.AES(key), 
            modes.CFB(iv), 
            backend=default_backend()
        ).encryptor()
        data = encryptor.update(data)+encryptor.finalize()
        data = base64.b64encode(data)
        return data
    except:
        print('ERROR ciphering',sys.exc_info())

def create_symetric_key():    
    pem_data = open('repository.crt','rb').read()
    certificate = x509.load_pem_x509_certificate(pem_data, default_backend())
    public_key = certificate.public_key()
    
    key_length = 192//8  #192 bits -> 24 bytes
    secret_key = os.urandom(key_length)
    
    cipheredkey = public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

    print('before encryption',secret_key)
    return secret_key, base64.b64encode(cipheredkey).decode('utf-8')


def signed_data(msg,encrypt=False):
    for slot in slots:
        session = pkcs11.openSession( slot )
        data = bytes(msg)
        privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),(CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]        
        signature = bytes(session.sign( privKey, data, Mechanism(CKM_SHA1_RSA_PKCS) ))
        certificate = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE)])[0]

        certDer = bytes(session.getAttributeValue( certificate, [CKA_VALUE], True )[0])

        session.closeSession()

        jsonToSend = {
            'data':json.loads(data.decode('utf-8')),
            'signature':base64.b64encode(signature).decode('utf-8'),
            'certificate':base64.b64encode(certDer).decode('utf-8')}

        if encrypt:
            sym_key, cipheredkey = create_symetric_key()
            cipherciphertext = encrypt_with_symetric_key(jsonToSend,sym_key)
            jsonToSend = { 
                'key': cipheredkey,
                'ciphertext': cipherciphertext.decode('utf-8'),
                'ciphersignature': sign_with_symetric_key(sym_key,cipherciphertext).decode('utf-8')
            }
            print('IMPORTANT  -> \n\n  ',jsonToSend,'\n\n')
            return json.dumps(jsonToSend)
        else:
            return json.dumps(jsonToSend)

  
from flask import Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app)
from flask import request, abort

@app.route("/",methods=['POST'])
def justsign():
    data=json.dumps(request.json,ensure_ascii=False,separators=(',',':'))
    print(type(data))
    
    return signed_data(data)

@app.route("/newblindbid",methods=['POST'])
def encryptandsign():
    if not request.json:
        abort(400)
    data=json.dumps(request.json,ensure_ascii=False,separators=(',',':'))
    print('ENCRYPTING')
    return signed_data(data,True)
