import os
import base64
import logging
import json

from utils.sec_utils import *
from utils.certificates_utils import *
from cryptography.hazmat.primitives.serialization import Encoding

sec_logger=logging.getLogger('SECURITY')

class CryptographyClient(object):
    def __init__(self, uuid, prv_key, pub_key, cipher_methods, log_time, cc_on, cc=None, cc_session=None, cc_pin=None):
        # logging basic stuff
        logging.basicConfig(filename='log/client_'+log_time+'.logs',
                                    filemode='a',
                                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                                    datefmt='%H:%M:%S',
                                    level=logging.DEBUG)
        # basic passages 
        self.uuid=uuid
        self.prv_key=prv_key
        self.pub_key=pub_key
        self.cipher_methods=cipher_methods

        # cc stuff
        self.cc_on=cc_on
        self.cc_pin=cc_pin
        if self.cc_on:
            self.cc=cc
            self.cc_cert=self.cc.get_pubKey_cert()
            self.cc_session=cc_session
        else:
            self.cc=None
            self.cc_cert=None
            self.cc_session=None

        # security stuff
        self.private_value=None     # ephemeral private key
        self.public_value=None      # ephemeral public key but it could be bread if coding was communist
        self.peer_public_value=None # also bread if communist
        self.peer_salt=None
        self.derivation_number=1
        self.previous_MAC=None
        self.salt_dict={}

    # send the first message
    # message has format: 
    # {
    #   'operation': 'player@sign_in',
    #   'message': decoded-base64-encoded-message json,
    #   'signature': signature to verify authenticity,
    #   'certificate': to verify chain of trust
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
                    'derivations': self.derivation_number,
                    'certificate': base64.b64encode(self.cc_cert.public_bytes(Encoding.PEM)).decode('utf-8'),
                }
            ).encode('utf-8')
        )
        # signing it
        sec_logger.debug('signing first message')
        if self.cc_on:
            if self.cc_pin:
                signature=base64.b64encode(self.cc.cc_sign(prep, session=self.cc_session, pin=self.cc_pin)).decode('utf-8')
            else:
                pin, session=self.cc.ask_pin()
                signature=base64.b64encode(self.cc.cc_sign(prep, session=session, pin=pin)).decode('utf-8')
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
            'operation': 'player@sign_in',
            'message': prep.decode('utf-8'),
            'signature': signature,
            'cipher_suite': self.cipher_methods
        }
        sec_logger.debug('first package is: \n'+str(package))
        return package

    # receive and decipher messages
    # message has format: 
    # {
    #   'operation': string,
    #   'message': decoded-base64-encoded-message json,
    #   'signature': signature to verify authenticity,
    #   'certificate': to verify chain of trust
    # }
    def decipher_secure_server_message(self, ciphered_message):
        sec_logger.debug('Deciphering secure message')

        # is first_message ?
        if self.prev_mac is None:
            peer_certificate=deserialize_cert(ciphered_message['certificate'])
            #MUST IMPLEMENT CERTIFICATE VALIDATION
