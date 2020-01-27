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

# cryptography actions for the game
class CryptographyServer(object):
    def __init__(self, logLevel='INFO'):
        # logging
        coloredlogs.install(level=logLevel, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=log_colors)
        security_logger.debug('Got security')

        # security
        self.sec_clients_dict={}

    # sign in of a user
    #   -> user can provide multiple ciphering methods
    #   -> user must provide a public key
    #   -> user must provide a name
    #   -> must use CC stuff
    def sign_in(self, player_addr, payload_day_0):
        security_logger.debug('Reached sign in to player '+str(player_addr))
        try:
            if not set({'message', 'operation','signature','cipher_suite', 'cc_user'}).issubset(set(payload_day_0.keys())):
                return {'operation': 'ERROR', 'error': 'wrong fields for operation player@sign_in'}
            security_logger.debug('player_addr: '+str(player_addr))
            security_logger.debug('player_payload: '+str(payload_day_0))
            decoded_message=json.loads(
                base64.b64decode(
                    payload_day_0['message'].encode('utf-8')
                ).decode()
            )
            cipher_methods=payload_day_0['cipher_suite']
            signature=base64.b64decode(
                payload_day_0['signature'].encode()
            )
            if payload_day_0['cc_user']:
                certificate=deserialize_cert(decoded_message['certificate'])
                publicKey=certificate.get_pubkey().to_cryptography_key()
                security_logger.debug('Checking signature')
            else:
                publicKey=deserialize_key(decoded_message['key'])
            try:
                valid_sign=verify(publicKey, signature, payload_day_0['message'].encode(), hash_alg=cipher_methods['asym']['sign']['hashing'], padding_mode=cipher_methods['asym']['sign']['padding'])
            except InvalidSignature:
                security_logger.debug('Received invalid signature from '+str(player_addr))
                return {'operation': 'ERROR', 'error': 'wrong signature'}
            security_logger.debug('Signature valid, checking certificat CoT')
           # self.sec_clients_dict.update({payload_day_0['uuid']: 
           #                               {
           #                                 'name': payload_day_0['name'],
           #                                 'public_key': payload_day_0['key'],
           #                                 'signature': payload_day_0['signature'],
           #                                 'cipher_methods': payload_day_0['cipher_methods'],
           #                                 'signature_method': payload_day_0['sig_method'],
           #                                 'address': player_addr
           #                               }})
            security_logger.debug('payload: '+str(payload_day_0))
        except Exception as e:
            security_logger.exception('Exception '+str(e)+' @ player_sign_in')
        pass

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

