# basic stuff
import os
import sys
import json
import time
import traceback
import socket
import uuid
from pprint import pprint
from _thread import *

# sec stuff
from cc_api import CC_API
from client_crypto import CryptographyClient
from utils.sec_utils import *
from cryptography.hazmat.primitives import hashes

# game stuff
from player import *

# to not debug with prints
import logging

# pretty up stuff
from bullet import *
from bullet import emojis
from termcolor import colored

# server stuff
BUFFER_SIZE=512*1024

# paths stuff
DIRNAME=os.path.dirname(os.path.realpath(__file__))
KEYS_PATH=os.path.join(DIRNAME, 'keys')
CERTS_PATH=os.path.join(DIRNAME, 'certs')

# client logging
client_logger=logging.getLogger('CLIENT')
log_time=str(int(time.time()))
logging.basicConfig(filename='log/client_'+log_time+'.logs',
                            filemode='a',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)
cc_api=CC_API()

class Client(object):
    def __init__(self, host='0.0.0.0', port=8080, logLevel='ERROR'):
        # client stuff
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username=''
        client_logger.setLevel(logLevel)

        # client security stuff
        self.uuid=None
        self.security=None

        # CC stuff
        self.cc_on=False
        self.cc_cert=None
        self.cc_pin=None
        self.cc_num=None

        # Game stuff
        self.player = Player()

        # start player
        self.connect()

    def send(self, payload, server_res=True):
        pprint(payload)
        data=json.dumps(payload)
        while len(data):
            self.sock.send(data[:BUFFER_SIZE].encode())
            data=data[BUFFER_SIZE:]
        if server_res:
            try:
                res=json.loads(self.sock(BUFFER_SIZE).decode())
                return res
            except Exception as e:
                client_logger.exception('Unexpected error: '+str(e))

    def pick_ciphers(self):
        hash_types=['MD5','SHA2','SH3']
        sym_alg_types=['AES','CAM','FER']
        sym_mode_types=['CBC','CTR','OFB','CFB','CFB8']
        padd_types=['OAEP','PKCS1v15','PSS']
        cli=YesNo(prompt='Do you wish to pick your cipher suite (default is SHA1-AES-CBC-OAEP-PSS-SHA3)? ')
        cl=cli.launch()
        if not cl:
            return get_cipher_methods("SHA2-AES-CBC-OAEP-PSS-SHA2")
        cli=SlidePrompt(
            [
                Bullet(
                        prompt='Regular hash method to use: ',
                        choices=hash_types,
                        align= 5, 
                        bullet="●",
                        bullet_color=colors.foreground["magenta"],
                        word_color=colors.foreground["white"],
                        word_on_switch=colors.foreground["black"],
                        background_color=colors.background["black"],
                        background_on_switch=colors.background["white"],
                        pad_right = 5
                ),
                Bullet(
                        prompt='Symmetric ciphering algorithm: ',
                        choices=sym_alg_types,
                        align= 5, 
                        bullet="●",
                        bullet_color=colors.foreground["magenta"],
                        word_color=colors.foreground["white"],
                        word_on_switch=colors.foreground["black"],
                        background_color=colors.background["black"],
                        background_on_switch=colors.background["white"],
                        pad_right = 5
                ),
                Bullet(
                        prompt='Symmetric ciphering mode: ',
                        choices=sym_mode_types,
                        align= 5, 
                        bullet="●",
                        bullet_color=colors.foreground["magenta"],
                        word_color=colors.foreground["white"],
                        word_on_switch=colors.foreground["black"],
                        background_color=colors.background["black"],
                        background_on_switch=colors.background["white"],
                        pad_right = 5
                ),
                Bullet(
                        prompt='Asymmetric ciphering padding: ',
                        choices=padd_types,
                        align= 5, 
                        bullet="●",
                        bullet_color=colors.foreground["magenta"],
                        word_color=colors.foreground["white"],
                        word_on_switch=colors.foreground["black"],
                        background_color=colors.background["black"],
                        background_on_switch=colors.background["white"],
                        pad_right = 5
                ),
                Bullet(
                        prompt='Asymmetric signing hashing: ',
                        choices=hash_types,
                        align= 5, 
                        bullet="●",
                        bullet_color=colors.foreground["magenta"],
                        word_color=colors.foreground["white"],
                        word_on_switch=colors.foreground["black"],
                        background_color=colors.background["black"],
                        background_on_switch=colors.background["white"],
                        pad_right = 5
                )
            ]
        )
        rez=cli.launch()
        types=[]
        for r in rez:
            types+=[r[1]]
        suite=types[0]+"-"+types[1]+'-'+types[2]+'-'+types[3]+'-PSS-'+types[4]
        client_logger.info('SUITE: '+suite)
        return get_cipher_methods(suite)

    def connect(self):
        print('##########################')
        print('#          LOGIN         #')
        print('##########################')
        print("#        INSERT CC       #")
        print('##########################')
        cli=YesNo(prompt='Will you be using CC? ')
        self.cc_on=cli.launch()
        client_logger.debug('CC - '+str(self.cc_on))

        if not self.cc_on:
            client_logger.debug('no cert')
            self.uuid=uuid.uuid1()
            client_logger.debug('uuid: '+str(self.uuid))
            cli=Input('Username: ')
            self.username=cli.launch()
            client_logger.debug('username: '+str(self.username))
        else:
            self.cc_cert=cc_api.get_pubKey_cert()
            client_logger.debug('cert: '+str(self.cc_cert))
            self.uuid=uuid.uuid1()
            client_logger.debug('uuid: '+str(self.uuid))
            self.username=cc_api.get_citizen_card_info()['name']
            client_logger.debug('username: '+str(self.username))
            self.cc_num=cc_api.get_citizen_card_info()['serialnumber']
            client_logger.debug('CC ID: '+str(self.cc_num))
            cli=YesNo(prompt='Save CC pin for later? ')
            if cli.launch():
                self.cc_pin=cc_api.ask_pin()

        # creating keys and user specs
        keys_dir= os.path.join(KEYS_PATH,str(self.uuid))
        if not os.path.exists(keys_dir):
            # pick sec_spec
            cipher_methods=self.pick_ciphers()
            client_logger.debug('cipher_methods: '+str(cipher_methods))
            # handling creation and storage of keys
            os.makedirs(keys_dir)
            rsa_private_key=generate_rsa()
            write_private_key(keys_dir, rsa_private_key, self.uuid)
            client_logger.debug('stored private key @ '+keys_dir)
            write_public_key(keys_dir, rsa_private_key.public_key(), self.uuid)
            client_logger.debug('stored public key @ '+keys_dir)

            # create secure client
            self.security=CryptographyClient(self.uuid, 
                                             rsa_private_key, rsa_private_key.public_key(),
                                             cipher_methods, 
                                             log_time,
                                             self.cc_on, cc_api, self.cc_pin,
                                             )
            first=self.send(self.security.secure_init_message(self.username))
            print(first)

client=Client(logLevel='DEBUG')

