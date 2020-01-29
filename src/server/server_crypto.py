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
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography import x509

# work bibs
from paths import *
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
        # secure clients db
        # has following format
        # sec_clients={
        #   <client_id|client_socket>:{
        #       'username':<string|name>,
        #       'certificate':<X509Certificate|client cert>,
        #       'client_public_key':<RSAPublicKey|client public rsa key>,
        #       'client_dh_value':<EllipticCurvePublicKey|client public ECDH value>,
        #       'derivations':<integer|number of hash derivations>
        #       'client_salt':<bytes|salt to derivation hash>,
        #       'cipher_methods':<string|client ciphering methods>,
        #       'cc_user':<boolean|client using pt e-id>,
        #       'pbk_sent':<boolean|has client received most recent public key>
        #       'private_dh_value': <EllipticCurvePrivateKey|server dh value for this client>
        #    }
        self.sec_clients_dict={}
        # load keystore
        security_logger.debug('Loading certificates')
        self.root_certificates, self.trusted_certificates, self.revoqued_lists=load_certificates(CC_CERTS_DIR, CC_CRL_DIR)
        security_logger.debug('Creating keystore')
        self.keystore=load_KeyStore(self.root_certificates, self.trusted_certificates, self.revoqued_lists)
        # load private and public RSA keys
        security_logger.debug('Loading keys')
        if not os.path.exists(os.path.join(KEYS_DIR, 'prv_key.rsa')):
            security_logger.debug('*Creating keys')
            self.private_key=generate_rsa()
            write_private_key(os.path.join(KEYS_DIR,'prv_key.rsa'), self.private_key)
            write_public_key(os.path.join(KEYS_DIR,'pub_key.rsa'), self.private_key.public_key())
        else:
            self.private_key=read_private_key(os.path.join(KEYS_DIR, 'prv_key.rsa'))
        self.public_key=self.private_key.public_key()
        self.old_private_key=self.private_key

    # sign in of a user
    #   -> user can provide multiple ciphering methods
    #   -> user must provide a public key
    #   -> user must provide a name
    #   -> must use CC stuff
    def sign_in(self, player_addr, payload_day_0):
        security_logger.debug('Reached sign in to player '+str(player_addr))
        try:
            if not set({'message', 'operation','signature','cipher_suite', 'cc_user'}).issubset(set(payload_day_0.keys())):
                return None, {'status': 'ERROR', 'error': 'wrong fields for operation client@register_player'}
            security_logger.debug('player_addr: '+str(player_addr))
            # parse received args
            decoded_message=json.loads(
                base64.b64decode(
                    payload_day_0['message'].encode('utf-8')
                ).decode()
            )
            if not set({'name','key','salt','derivations','certificate','dh_value'}).issubset(set(decoded_message.keys())):
                return None, {'status': 'ERROR', 'error': 'wrong fields in security data for operation client@register_player'}
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
                valid_sign=verify(
                    publicKey, 
                    signature, 
                    payload_day_0['message'].encode(), 
                    hash_alg=cipher_methods['asym']['sign']['hashing'], 
                    padding_mode=cipher_methods['asym']['sign']['padding']
                )
            except InvalidSignature:
                security_logger.debug('Received invalid signature from '+str(player_addr))
                return None, {'status': 'ERROR', 'error': 'wrong signature'}
            security_logger.debug('Signature valid, checking certificat CoT')
            # check certificate validity - MISSING: OCSP check && NOT USING: CoT verification
            if payload_day_0['cc_user']:
                certificate=deserialize_cert(decoded_message['certificate'])
                if certificate.has_expired():
                    security_logger.warning('Received expired certificate')
                    return None, {'status': 'ERROR', 'error': 'expired certificate'}
                if not verify_certificate_CoT(certificate, self.keystore):
                    security_logger.warning('Received invalid certificate')
                    #return None, {'status': 'ERROR', 'error': 'invalid certificate'}
            security_logger.debug('all is well in the certificate and signature')
            # create client (it's a dict)
            client={
                'username':decoded_message['name'],
                'certificate':deserialize_cert(decoded_message['certificate']),
                'client_public_key':deserialize_key(decoded_message['key']),
                'client_dh_value':deserialize_key(decoded_message['dh_value']),
                'derivations':decoded_message['derivations'],
                'client_salt':base64.b64decode(decoded_message['salt'].encode()),
                'cipher_methods':payload_day_0['cipher_suite'],
                'cc_user':payload_day_0['cc_user'],
                'pbk_sent':False
            }
            security_logger.info('new client validated, ready to accept')
            self.sec_clients_dict.update({player_addr: client})
            return client, {'status': 'success'} 
        except Exception as e:
            security_logger.exception('Exception '+str(e)+' @ player_sign_in')
        return None, None

    # secures packages to send them
    # format of sent secure package
    # {
    #   'operation': <string>,
    #   'mac': <decoded-base64encoded-bytes>,
    #   'cipher_suite': <string>,
    #   'signature': <decoded-base64encoded-bytes>,
    #   'public_key': <serializedpublickey>,
    #   'package': (base64encoded-encoded) 
    #       {
    #           'message': <decoded-base64encoded-ciphertext>,
    #           'dh_public_value': <serialized_public_key>,
    #           'salt': <decoded-base64encoded-bytes>,
    #           'iv': <decoded-base64encoded-bytes>,
    #           'derivation': <integer>
    #       }
    # }
    def secure_package(self, player_addr, message, operation, update_public_key=False):
        security_logger.debug('calculating private values')
        # Values used in key exchange
        self.sec_clients_dict[player_addr]['salt']=os.urandom(16)
        self.sec_clients_dict[player_addr]['private_dh_value']=generate_dh()
        # Derive DH key and cipher message
        security_logger.debug('generating ECDH key')
        dh_key = generate_key_dh(
            self.sec_clients_dict[player_addr]['private_dh_value'],
            self.sec_clients_dict[player_addr]['client_dh_value'],
            self.sec_clients_dict[player_addr]['salt'],
            self.sec_clients_dict[player_addr]['client_salt'],
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['key_size'],
            self.sec_clients_dict[player_addr]['cipher_methods']['hash'],
            self.sec_clients_dict[player_addr]['derivations'],
        )
        security_logger.debug('generating ECDH cipher and ciphering message to send')
        dh_cipher, dh_iv = generate_sym_cipher(
            dh_key, 
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['mode'], 
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['algorithm']
        )
        encryptor=dh_cipher.encryptor()
        sym_padding=PKCS7(
            get_cipher_alg(
                self.sec_clients_dict[player_addr]['cipher_methods']['sym']['algorithm'],
                dh_key
            ).block_size
        ).padder()
        ciphered_message=encryptor.update(
            sym_padding.update(
                json.dumps(message).encode()
            )+sym_padding.finalize()
        )+encryptor.finalize()
        security_logger.debug('generating package')
        package=base64.b64encode(
            json.dumps(
                {
                    'message': base64.b64encode(ciphered_message).decode('utf-8'),
                    'dh_public_value': serialize_key(self.sec_clients_dict[player_addr]['private_dh_value'].public_key()),
                    'salt': base64.b64encode(self.sec_clients_dict[player_addr]['salt']).decode('utf-8'),
                    'iv': base64.b64encode(dh_iv).decode('utf-8'),
                    'derivation': self.sec_clients_dict[player_addr]['derivations']
                }
            ).encode('utf-8')
        )
        security_logger.debug('generating MAC')
        mac=base64.b64encode(
            generate_mac(
                    dh_key,
                    package,
                    self.sec_clients_dict[player_addr]['cipher_methods']['hash'],
                )
            ).decode('utf-8')
        security_logger.debug('checing if it has to send new key')
        if not self.sec_clients_dict[player_addr]['pbk_sent'] or update_public_key:
            security_logger.info('Updating client %s with new server key', player_addr)
            signature=base64.b64encode(
                sign(
                    self.old_private_key,
                    package,
                    self.sec_clients_dict[player_addr]['cipher_methods']['asym']['sign']['hashing'],
                    self.sec_clients_dict[player_addr]['cipher_methods']['asym']['sign']['padding'],
                )
            ).decode('utf-8')
            message = {
                'operation': operation,
                'package': package.decode('utf-8'),
                'mac': mac,
                'signature': signature,
                'public_key': serialize_key(self.public_key),
                'cipher_suite': self.sec_clients_dict[player_addr]['cipher_methods']
            }
            self.sec_clients_dict[player_addr]['pbk_sent']=True
        else:
            message = {
                'operation': operation,
                'package': package.decode('utf-8'),
                'mac': mac,
                'cipher_suite': self.sec_clients_dict[player_addr]['cipher_methods']
            }
        security_logger.debug('Message secured, proceedto launching it to bad spaces, like star trek or classes with Maria')
        return message

    # opens secure messages
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
    #           'dh_public_value': <serialized_public_key>,
    #           'salt': <decoded-base64encoded-bytes>,
    #           'iv': <decoded-base64encoded-bytes>,
    #           'derivation': <integer>
    #       }
    # }
    def parse_security(self, player_addr, secure_package):
        # Check all payload fields and specs
        if not set({'operation', 'package', 'cipher_suite', 'mac'}).issubset(set(secure_package.keys())):
            security_logger.warning('incomplete message received from client %s', player_addr)
            return {'operation': 'ERROR', 'error': 'incomplete message'}
        if secure_package['cipher_suite']!=self.sec_clients_dict[player_addr]['cipher_methods']:
            security_logger.warning('%s changed cipher specs without warning', player_addr)
            return {'operation': 'ERROR', 'error': 'bad cipher specs'}
        # passing to payload parsing
        package=json.loads(
            base64.b64decode(
                message['package'].encode()
            ).decode('utf-8')
        )
        if not set({'dh_public_value','salt','iv','derivation','message'}).issubset(set(package.keys())):
            sec_logger.warning('incomplete message received from server')
            return {'operation': 'ERROR', 'error': 'incomplete message'}
        # Derive key and decipher payload
        self.sec_clients_dict[player_addr]['derivations']=payload['derivation']
        self.sec_clients_dict[player_addr]['client_public_value']=deserialize_key(payload['dh_public_value'])
        self.sec_clients_dict[player_addr]['client_salt']=base64.b64decode(payload['salt'].encode())
        dh_key = generate_key_dh(
            self.sec_clients_dict[player_addr]['private_dh_value'],
            self.sec_clients_dict[player_addr]['client_dh_value'],
            self.sec_clients_dict[player_addr]['salt'],
            self.sec_clients_dict[player_addr]['client_salt'],
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['key_size'],
            self.sec_clients_dict[player_addr]['cipher_methods']['hash'],
            self.sec_clients_dict[player_addr]['derivations'],
        )
        # Verify MAC to make sure of message integrity
        if not verify_mac(
                dh_key, 
                secure_package['package'].encode('utf-8'),
                base64.b64decode(secure_package['mac'].encode('utf-8')),
                self.sec_clients_dict[player_addr]['cipher_methods']['hash']):
            security_logger.info('received message with wrong MAC from player %s', player_addr)
            return {'type': 'error', 'error': "Invalid MAC; dropping message"}
        # Decipher secure package
        security_logger.debug('generating ECDH cipher and deciphering message to send')
        dh_cipher, dh_iv = generate_sym_cipher(
            dh_key, 
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['mode'], 
            self.sec_clients_dict[player_addr]['cipher_methods']['sym']['algorithm'],
            base64.b64decode(
                base64.b64decode(
                    package
                )['iv'].encode('utf-8')
            )
        )
        # Decipher message
        if 'message' in package:
            decryptor=dh_cipher.decryptor()
            message=decryptor.update(
                base64.b64decode(
                    package['message'].encode('utf-8')
                )
            )+decryptor.finalize()
            message=json.loads(message.decode('utf-8'))
        else:
            security_logger.info('received message without content from player %s', player_addr)
            return {'type': 'error', 'error': "no content"}
        # check if client has new public key
        if set({'signature','public_key'}).issubset(set(secure_package.keys())):
            security_logger.warning('client %s signaled an update to it\'s public key, trialing with old key signature', player_addr)
            signature=base64.b64decode(
                secure_package['signature'].encode()
            )
            # picking method to check sign, depends if cc is on or not
            if self.sec_clients_dict[player_addr]['cc_user']:
                certificate=self.sec_clients_dict[player_addr]['client_public_key']
                publicKey=certificate.get_pubkey().to_cryptography_key()
                security_logger.debug('Checking signature')
            else:
                publicKey=self.sec_clients_dict[player_addr]['client_public_key']
            try:
                valid_sign=verify(
                    publicKey, 
                    signature,
                    secure_package['package'].encode('utf-8'),
                    hash_alg=self.sec_clients_dict['cipher_methods']['asym']['sign']['hashing'],
                    padding_mode=self.sec_clients_dict['cipher_methods']['asym']['sign']['hashing']
                )
                self.sec_clients_dict[player_addr]['client_public_key']=deserialize_key(secure_package['public_key'])
            except InvalidSignature:
                security_logger.debug('Received invalid signature from '+str(player_addr)+' , discarding this package')
                return {'type': 'error', 'error': 'Bad new key'}
        security_logger.debug('finished process of deciphering message from %s', player_addr)
        return message

    # update inner keys
    def update_keys(self, new_private_key):
        self.old_private_key=self.private_key
        self.private_key=new_private_key
        self.public_key=new_private_key.public_key()
        write_private_key(os.path.join(KEYS_DIR,'prv_key.rsa'), self.private_key)
        for player in list(self.sec_clients_dict.keys()):
            self.sec_clients_dict[pla]['pbk_sent']=False        
        #[self.sec_clients_dict[pla]['pbk_sent']=False for pla in list(self.sec_clients_dict.keys())]
