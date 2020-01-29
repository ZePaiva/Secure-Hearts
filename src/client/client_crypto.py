import os
import base64
import logging
import json

from utils.sec_utils import *
from utils.certificates_utils import *
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.padding import PKCS7

sec_logger=logging.getLogger('SECURITY')

class CryptographyClient(object):
    def __init__(self, log_level, prv_key, pub_key, server_public_key, cipher_methods, log_time, cc_on, cert=None, cc=None):
        # logging basic stuff
        logging.basicConfig(filename='log/client_'+log_time+'.logs',
                                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.DEBUG)
        sec_logger.setLevel(log_level)
        # basic passages 
        self.prv_key=prv_key
        self.pub_key=pub_key
        self.cipher_methods=cipher_methods

        # cc stuff
        self.cc_on=cc_on
        if self.cc_on:
            self.cc=cc
            self.cc_cert=self.cc.get_pubKey_cert()
        else:
            self.cc=None
            self.cc_cert=cert

        # security stuff
        self.private_value=None                              # ephemeral private key
        self.old_private_key=None                            # needed to alter key in runtime
        self.public_value=None                               # ephemeral public key but it could be bread if coding was communist
        self.other_public_value={'server':None}              # also bread if communist
        self.other_public_key={'server':server_public_key}   # also bread if communist
        self.other_salts={'server':None}
        self.derivations={'server':1}
        self.salt_dict={}             # used to store server and other clients salts
        self.prev_mac=None

    # send the first message
    # message has format: 
    # {
    #   'operation': 'player@sign_in',
    #   'message': decoded-base64-encoded-message json,
    #   'signature': signature to verify authenticity,
    #   'cipher_suite': cipher methods
    # }
    def secure_init_message(self, username):
        # generate ephemeral keys
        sec_logger.debug('Generating ECDH key pair')
        self.private_value=generate_dh()
        self.public_value=self.private_value.public_key()
        # going to salinas to get some salt
        sec_logger.debug('Generating salt')
        first_salt=os.urandom(16)
        self.salt_dict.update({'server':[]})
        self.salt_dict['server']+=[first_salt]

        # creating message 
        sec_logger.debug('creating first message')
        prep=base64.b64encode(
            json.dumps(
                {
                    'name': username,
                    'key': serialize_key(self.pub_key),
                    'salt': base64.b64encode(first_salt).decode('utf-8'),
                    'derivations': self.derivations['server'],
                    'certificate': serialize_cert(self.cc_cert),
                    'dh_value': serialize_key(self.public_value)
                }
            ).encode('utf-8')
        )
        # sec_logger.debug("message:\n"+str(prep))
        # signing it
        sec_logger.debug('signing first message')
        if self.cc_on:
                signature=base64.b64encode(self.cc.cc_sign(prep)).decode('utf-8')
        else:
            signature=base64.b64encode(
                sign(
                    self.prv_key, 
                    prep, 
                    self.cipher_methods['asym']['sign']['hashing'], 
                    self.cipher_methods['asym']['sign']['padding']
                )
            ).decode('utf-8')
        # creating package
        sec_logger.debug('packaging first message')
        package={
            'operation': 'client@register_crypto',
            'message': prep.decode('utf-8'),
            'signature': signature,
            'cipher_suite': self.cipher_methods,
            'cc_user': self.cc_on
        }
        sec_logger.debug('first package received')
        self.prev_mac=1
        return package

    # cipher server messages
    def server_secure_package(self, package, operation, update_public_key=False):
        sec_logger.debug('Ciphering secure message')
        # Calculating values to use in key exchange 
        salt = os.urandom(16)
        self.salt_dict['server']+=[salt]
        self.derivations['server']+=1
        # Derive DH key and cipher payload
        sec_logger.debug('generating ECDH key')
        dh_key = generate_key_dh(
            self.private_value,
            self.other_public_value['server'],
            salt,
            self.other_salts['server'],
            self.cipher_methods['sym']['key_size'],
            self.cipher_methods['hash'],
            self.derivations['server'],
        )
        # generating cipher
        sec_logger.debug('generating ECDH cipher and ciphering message to send')
        dh_cipher, dh_iv = generate_sym_cipher(
            key, 
            self.cipher_methods['sym']['mode'], 
            self.cipher_methods['sym']['algorithm']
        )
        # generating ciphertext
        encryptor=dh_cipher.encryptor()
        ciphered_message=encryptor.update(
            json.dumps(package).encode()
        )+encryptor.finalize()
        sec_logger.debug('generating package')
        package=base64.b64encode(
            json.dumps(
                {
                    'message': base64.b64encode(ciphered_message).decode('utf-8'),
                    'security_data': {
                        'dh_public_value': serialize_key(self.public_value),
                        'salt': base64.b64encode(salt).decode('utf-8'),
                        'iv': base64.b64encode(dh_iv).decode('utf-8'),
                        'derivation': self.derivations['server']
                    }
                }
            ).encode('utf-8')
        )
        # Generate MAC
        sec_logger.debug('generating MAC')
        mac=base64.b64encode(
            generate_mac(
                    dh_key,
                    package,
                    self.cipher_methods['sym']['key_size'],
                )
            ).decode('utf-8')
        self.prev_mac = mac
        # Build message
        sec_logger.debug('generating message to send')
        if update_public_key:
            sec_logger.info('Updating server with new public key')
            if self.cc_on:
                    signature=base64.b64encode(self.cc.cc_sign(prep)).decode('utf-8')
            else:
                signature=base64.b64encode(
                    sign(
                        self.prv_key, 
                        prep, 
                        self.cipher_methods['asym']['sign']['hashing'], 
                        self.cipher_methods['asym']['sign']['padding']
                    )
                ).decode('utf-8')
            message = {
                'operation': operation,
                'package': package.decode('utf-8'),
                'mac': mac,
                'signature': signature,
                'public_key': serialize_key(self.pub_key),
                'cipher_suite': self.cipher_methods
            }
        else:
            message = {
                'operation': operation,
                'package': package.decode('utf-8'),
                'mac': mac,
                'cipher_suite': self.cipher_methods
            }
        sec_logger.debug('Message secured, proceedto launching it to bad spaces, like star trek or classes with Maria')
        return message

    # deciphers received messages from server
    # format of received secure package
    # {
    #   'operation': <string>,
    #   'mac': <decoded-base64encoded-bytes>,
    #   'cipher_suite': <string>,
    #   'signature': <decoded-base64encoded-bytes | uses old key>,
    #   'public_key': <serializedpublickey>,
    #   'package': (base64encoded-encoded) 
    #       {
    #           'message': <decoded-base64encoded-ciphertext>,
    #           'security_data':
    #               {
    #                   'dh_public_value': <serialized_public_key>,
    #                   'salt': <decoded-base64encoded-bytes>,
    #                   'iv': <decoded-base64encoded-bytes>,
    #                   'derivation': <integer>
    #               }
    #       }
    # }
    def server_parse_security(self, secure_package):
        # Check all payload fields and specs
        if not set({'operation', 'package', 'cipher_suite', 'mac'}).issubset(set(secure_package.keys())):
            sec_logger.warning('incomplete message received from server')
            return {'operation': 'ERROR', 'error': 'incomplete message'}
        if secure_package['cipher_suite']!=self.cipher_methods:
            sec_logger.warning('server changed cipher specs without warning')
            return {'operation': 'ERROR', 'error': 'bad cipher specs'}
        # checking if have received ghost message or server message
        if not self.prev_mac:
            sec_logger.warning('got weird message, disposing')
            return {'operation': 'ERROR', 'error': 'no question'}
        if self.prev_mac==1:
            if not set({'signature','public_key'}).issubset(set(secure_package.keys())):
                sec_logger.warning('got weird message, disposing')
                return {'operation': 'ERROR', 'error': 'wrong type of message'}
            pkey=deserialize_key(secure_package['public_key'])
            signature=base64.b64decode(
                secure_package['signature'].encode()
            )
            try:
                valid_sign=verify(
                    pkey, 
                    signature,
                    secure_package['package'].encode('utf-8'),
                    hash_alg=self.cipher_methods['asym']['sign']['hashing'],
                    padding_mode=self.cipher_methods['asym']['sign']['padding']
                )
            except InvalidSignature:
                sec_logger.debug('Received invalid signature from server , discarding this package')
                return {'type': 'error', 'error': 'Bad new key'}
        # passing to payload parsing
        package=json.loads(
            base64.b64decode(
                secure_package['package'].encode()
            ).decode('utf-8')
        )
        # Derive key and decipher payload
        salt=self.derivations['server']-1
        self.other_public_value['server']=deserialize_key(package['security_data']['dh_public_value'])
        self.other_salts['server']=base64.b64decode(package['security_data']['salt'].encode('utf-8'))
        dh_key = generate_key_dh(
            self.private_value,
            self.other_public_value['server'], 
            self.other_salts['server'],
            self.salt_dict['server'][salt],
            self.cipher_methods['sym']['key_size'],
            self.cipher_methods['hash'],
            self.derivations['server'],
        )
        # Decipher secure package
        sec_logger.debug('generating ECDH cipher and deciphering message to send')
        dh_cipher, dh_iv = generate_sym_cipher(
            dh_key, 
            self.cipher_methods['sym']['mode'], 
            self.cipher_methods['sym']['algorithm'],
            base64.b64decode(
                package['security_data']['iv'].encode('utf-8')
            )
        )
        # Decipher message
        if 'message' in package:
            decryptor=dh_cipher.decryptor()
            sym_padding=PKCS7(
                get_cipher_alg(
                    self.cipher_methods['sym']['algorithm'],
                    dh_key
                ).block_size
            ).unpadder()
            message=sym_padding.update(
                decryptor.update(
                    base64.b64decode(
                        package['message'].encode('utf-8')
                    )
                )+decryptor.finalize()
            )+sym_padding.finalize()
            message=json.loads(message.decode('utf-8'))
        else:
            sec_logger.info('received message without content from server')
            return {'type': 'error', 'error': "no content"}
        # check if server has new public key
        if set({'signature','public_key'}).issubset(set(secure_package.keys())):
            sec_logger.warning('server signaled an update to it\'s public key, trialing with old key signature')
            signature=base64.b64decode(
                secure_package['signature'].encode()
            )
            try:
                valid_sign=verify(
                    self.other_public_key['server'], 
                    signature,
                    secure_package['package'].encode('utf-8'),
                    hash_alg=self.cipher_methods['asym']['sign']['hashing'],
                    padding_mode=self.cipher_methods['asym']['sign']['padding']
                )
                self.other_public_key['server']=deserialize_key(secure_package['public_key'])
            except InvalidSignature:
                sec_logger.debug('Received invalid signature from server, discarding this package')
                return {'type': 'error', 'error': 'Bad new key'}
        sec_logger.debug('finished process of deciphering message')
        return message
