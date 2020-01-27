# basic stuff
import os
import sys
import json
import time
import traceback
import socket
import uuid
import select
from pprint import pprint
from termcolor import colored

# sec stuff
from cc_api import CC_API
from client_crypto import CryptographyClient
from utils.sec_utils import *
from utils.certificates_utils import *
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

class SecureClient(object):
    def __init__(self, host='0.0.0.0', port=8080, logLevel='ERROR'):
        # client stuff
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username=''
        client_logger.setLevel(logLevel)

        # server interaction
        self.input_buffer=''
        self.output_buffer=''

        # client security stuff
        self.uuid=None
        self.security=None

        # CC stuff
        self.cc_api=None
        self.cc_on=False
        self.cc_cert=None
        self.cc_pin=None
        self.cc_num=None
        self.cc_session=None

        # Game stuff
        self.player = Player()

        # start player
        self.connect()

    def close(self, error=None):
        if error:
            client_logger.warning("Client had unexpected error: %s", error)
        client_logger.debug('Closing client...')
        try:
            self.sock.close()
        except Exception as e:
            client_logger.exception('Error closing socket')
        client_logger.debug('Client deleted')
        print('GOODBYE !!!')
        exit(0)

    def clear_socket_inputs(self):
        payload=None
        try:
            payload=self.sock.recv(BUFFER_SIZE).decode()
            client_logger.debug('Message: '+str(payload))
        except:
            client_logger.exception('Error cleaning client '+str(sock)+' input')
            self.close(error='Error in input buffer, please check received messages')
        if payload:
            self.input_buffer+=payload
            # handler
        else:
            # handler
            pass

    def clear_socket_outputs(self):
        try:
            payload=self.output_buffer[:BUFFER_SIZE]
            client_logger.debug('Sending package '+str(payload)+' to '+str(self.sock))
            bytes_sent=self.sock.send(payload.encode())
            client_logger.debug('Message: '+str(self.output_buffer[:bytes_sent]))
            self.output_buffer=self.output_buffer[bytes_sent:]
        except Exception as e:
            client_logger.exception('Error cleaning client '+str(self.sock)+' output')
            self.close(error='Error in output buffer, please check sent messages')

    # must check this link to understand (it's adapted from it)
    # https://steelkiwi.com/blog/working-tcp-sockets/
    def listen(self):
        client_logger.info('Now listening')
        while True:
            inputs=[self.sock]
            outputs=[]
            # check if server has unanswered questions
            if self.output_buffer:
                outputs+=[self.sock]
            readable, writable, exceptional = select.select(inputs, outputs, inputs, 1000)
            client_logger.debug('Handling sockets inputs')
            for sock in readable:
                self.clear_socket_inputs()
            client_logger.debug('Handling sockets outputs')
            for sock in writable:
                self.clear_socket_outputs()
            client_logger.debug('Handling sockets with errors')
            for sock in exceptional:
                self.close()

    def pick_ciphers(self):
        hash_types=['MD5','SHA2','SHA3']
        sym_alg_types=['AES','CAM','FER']
        sym_mode_types=['CBC','CTR','OFB','CFB','CFB8']
        padd_types=['OAEP','PKCS1v15','PSS']
        if self.cc_on:
            cli=YesNo(prompt='Do you wish to use default cipher suite (SHA2-AES-CBC-OAEP-PKCS1v15-SHA2)? ')
        else:
            cli=YesNo(prompt='Do you wish to use default cipher suite (SHA2-AES-CBC-OAEP-PSS-SHA2)? ')
        cl=cli.launch()
        if cl:
            if self.cc_on:
                return get_cipher_methods("SHA2-AES-CBC-OAEP-PKCS1v15-SHA2")
            else:
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
                        choices=hash_types[1:],
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
        if self.cc_on:
            suite=types[0]+"-"+types[1]+'-'+types[2]+'-'+types[3]+'-PKCS1v15-'+types[4]
        else:
            suite=types[0]+"-"+types[1]+'-'+types[2]+'-'+types[3]+'-PSS-'+types[4]
        client_logger.info('SUITE: '+suite)
        return get_cipher_methods(suite)

    def connect(self):
        print('+------------------------+')
        print('|       CONNECTING       |')
        print('+------------------------+')
        cli=YesNo(prompt='Will you be using CC? ')
        self.cc_on=cli.launch()
        client_logger.debug('CC - '+str(self.cc_on))

        if not self.cc_on:
            self.cc_api=None
            client_logger.debug('no cc')
            self.uuid=uuid.uuid1()
            client_logger.debug('uuid: '+str(self.uuid))
            cli=Input('Username: ')
            self.username=cli.launch()
            client_logger.debug('username: '+str(self.username))
            self.cc_cert=generate_certificate(self.username)[0]
            client_logger.debug('cert: '+str(self.cc_cert))
        else:
            #try:
                client_logger.debug('cc api DOWN')
                self.cc_api=CC_API()
                client_logger.debug('cc api UP')
                self.cc_cert=self.cc_api.get_pubKey_cert()
                client_logger.debug('cert: '+str(self.cc_cert))
                self.uuid=uuid.uuid1()
                client_logger.debug('uuid: '+str(self.uuid))
                self.username=self.cc_api.get_citizen_card_info()['name']
                client_logger.debug('username: '+str(self.username))
                self.cc_num=self.cc_api.get_citizen_card_info()['serialnumber']
                client_logger.debug('CC ID: '+str(self.cc_num))
            #except Exception as e:
            #    client_logger.warning('NO PT eID INSERTED')
            #    print(colored("NO PT eID INSERTED", 'red'))
            #    client_logger.exception(e)

        # pick sec_spec
        cipher_methods=self.pick_ciphers()
        client_logger.debug('cipher_methods: '+str(cipher_methods))

        # creating keys and user specs
        keys_dir= os.path.join(KEYS_PATH,str(self.uuid))
        if not os.path.exists(keys_dir):
            # handling creation and storage of keys
            os.makedirs(keys_dir)
            rsa_private_key=generate_rsa()
            write_private_key(keys_dir, rsa_private_key)
            client_logger.debug('stored private key @ '+keys_dir)
            write_public_key(keys_dir, rsa_private_key.public_key())
            client_logger.debug('stored public key @ '+keys_dir)
        else:
            rsa_private_key=read_private_key(keys_dir)
            client_logger.debug('loaded private key from '+keys_dir)

        # create secure client
        self.security=CryptographyClient(self.uuid, 
                                         rsa_private_key, rsa_private_key.public_key(),
                                         cipher_methods, 
                                         log_time,
                                         self.cc_on, self.cc_cert, self.cc_api
                                         )
        self.output_buffer+=json.dumps(self.security.secure_init_message(self.username))
