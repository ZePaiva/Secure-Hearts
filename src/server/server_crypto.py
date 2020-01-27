# to not debug with prints
import logging
import coloredlogs
from termcolor import colored
# to work
import socket
import sys
import json
import traceback
import time
import uuid
import base64
from pprint import pprint

# crypto modules
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography import x509

# work bibs
from hearts import *
from croupier import *
from utils.server_utils import *
from utils.sec_utils import *
from utils.certificates_utils import *

# server logging
log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
security_logger=logging.getLogger('SECURITY')

DIR_PATH=os.path.dirname(os.path.realpath(__file__))
KEYS=os.path.join(DIR_PATH, 'keys')
CERTS=os.path.join(DIR_PATH, 'certs')

# cryptography actions for the game
class CryptographyServer(object):
    def __init__(self, logLevel='INFO'):
        # logging
        coloredlogs.install(level=logLevel, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=log_colors)
        security_logger.debug('Got security')

        # security
        self.sec_clients_dict={}
        certs_dir=os.path.join(CERTS,'CCCerts')
        crl_dir=os.path.join(CERTS,'CCCRL')
        self.root_certificates, self.trusted_certificates, self.revoqued_lists=load_certificates(certs_dir, crl_dir)
        self.keystore=load_KeyStore(self.root_certificates, self.trusted_certificates, self.revoqued_lists)
        if not os.path.exists(os.path.join(KEYS, 'prv_key.rsa')):
            self.private_key=generate_rsa()
            write_private_key(os.path.join(KEYS,'prv_key.rsa'), self.private_key)
        else:
            self.private_key=read_private_key(os.path.join(KEYS, 'prv_key.rsa'))
        self.public_key=self.private_key.public_key()

    # sign in of a user
    #   -> user can provide multiple ciphering methods
    #   -> user must provide a public key
    #   -> user must provide a name
    #   -> must use CC stuff
    def sign_in(self, player_addr, payload_day_0):
        security_logger.debug('Reached sign in to player '+str(player_addr))
        try:
            if not set({'message', 'operation','signature','cipher_suite', 'cc_user'}).issubset(set(payload_day_0.keys())):
                return None, {'operation': 'ERROR', 'error': 'wrong fields for operation player@sign_in'}
            security_logger.debug('player_addr: '+str(player_addr))
            security_logger.debug('player_payload: '+str(payload_day_0))
            # parse received args
            decoded_message=json.loads(
                base64.b64decode(
                    payload_day_0['message'].encode('utf-8')
                ).decode()
            )
            if not set({'name','key','salt','derivations','certificate'}).issubset(set(decoded_message.keys())):
                return None, {'operation': 'ERROR', 'error': 'wrong fields for operation player@sign_in'}
            cipher_methods=payload_day_0['cipher_suite']
            signature=base64.b64decode(
                payload_day_0['signature'].encode()
            )
            # picking method to check sign, depends if cc is on or not
            if payload_day_0['cc_user']:
                certificate=deserialize_cert(decoded_message['certificate'])
                publicKey=certificate.get_pubkey().to_cryptography_key()
                security_logger.debug('Checking signature')
            else:
                publicKey=deserialize_key(decoded_message['key'])
            # check sign validity
            try:
                valid_sign=verify(publicKey, signature, payload_day_0['message'].encode(), hash_alg=cipher_methods['asym']['sign']['hashing'], padding_mode=cipher_methods['asym']['sign']['padding'])
            except InvalidSignature:
                security_logger.debug('Received invalid signature from '+str(player_addr))
                return None, {'operation': 'ERROR', 'error': 'wrong signature'}
            security_logger.debug('Signature valid, checking certificat CoT')
            # check certificate validity - MISSING: OCSP check
            if payload_day_0['cc_user']:
                certificate=deserialize_cert(decoded_message['certificate'])
                if certificate.has_expired():
                    security_logger.warning('Received expired certificate')
                    return None, {'operation': 'ERROR', 'error': 'expired certificate'}
                if not verify_certificate_CoT(certificate, self.keystore):
                    security_logger.warning('Received invalid certificate')
                    return None, {'operation': 'ERROR', 'error': 'invalid certificate'}
            security_logger.debug('all is well in the certificate and signature')
            # create client (it's a dict)
            client={
                'username':decoded_message['name'],
                'certificate':deserialize_cert(decoded_message['certificate']),
                'public_key':deserialize_key(decoded_message['key']),
                'derivations':decoded_message['derivations'],
                'salt':base64.b64decode(decoded_message['salt'].encode()),
                'cipher_methods':payload_day_0['cipher_suite'],
                'cc_user':payload_day_0['cc_user']
            }
            security_logger.info('new client validated, ready to accept')
            self.sec_clients_dict.update({player_addr: client})
            return client, {'operation': 'sign_in', 'status': 'success'} 
        except Exception as e:
            security_logger.exception('Exception '+str(e)+' @ player_sign_in')
        return None, None

    # secures json packages(messages)
    def secure_package(self, message):
        return message

    # start card distribution
    #   -> create deck and server-side signature
    def start_card_distribution(self, starter_uuid):
        security_logger.debug('Reached start distribution card to player '+str(player_addr))

    # get all signatures
    #   -> get all hand signatures (must check if this is useful)
    def cards_signature(self, player, signature):
        security_logger.debug('Reached get cards signature to player '+str(player_addr))

    # check fraud
    #   -> must see which are the valid hands
    #   -> willl have to ask both players for their hand and signature
    def fraud_called(self, bad_player_hand, good_player_hand):
        security_logger.debug('Reached get cards signature to player '+str(player_addr))

