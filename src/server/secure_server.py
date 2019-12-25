# to not debug with prints
import logging
import coloredlogs

# server stuff
import select
import socket
import sys
import json
import traceback
import time
import uuid
from pprint import pprint
from _thread import *

# work bibs
from hearts import *
from croupier import *
from utils.server_utils import *
from utils.server_utils import *
from server_crypto import *

# server logging
server_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
server_logger=logging.getLogger('SERVER')

# buffers stuff
BUFFER_SIZE=512*1024

class SecureServer(object):
    def __init__(self, host, port, logLevel):
        # logging
        coloredlogs.install(level=logLevel, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=server_log_colors)

        # server socket startup
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(0)
        self.sock.bind((host,port))
        self.sock.listen(4)
        server_logger.info('Server located @ HOST='+host+' | PORT='+str(port))
        server_logger.debug('server up')

        # game stuff 
        self.croupier=Croupier(deck=cards)
        self.current_player_idx=None
        self.cards_on_table=[]
        self.current_suite=None
        self.game_over=False
        self.clients={}
        self.previous_plays=[]
        server_logger.debug('croupier up')

        # security stuff
        self.crypto_actions=CryptographyServer(logLevel)
        server_logger.debug('crypto up')

    def client_accept(self, client_socket, client_addr):
        if client_socket in self.clients:
            server_logger.warning('Client %s already exists', client_socket)
            return
        self.clients[client_socket]={'address': client_addr, 'input_buffer': '', 'output_buffer': ''}
        server_logger.debug('Added client '+str(client_socket))
        self.game_check()

    def client_remove(self, client_socket):
        if client_socket not in self.clients:
            server_logger.warning("Client %s doesn't exist", client_socket)
            return
        del self.clients[client_socket]
        server_logger.debug('Deleting client '+str(client_socket))
        client_socket.close()
        server_logger.debug('Client deleted')

    def clear_socket_inputs(self, sock):
        payload=None
        try:
            payload=sock.recv(BUFFER_SIZE).decode()
            server_logger.debug('Message: '+str(payload))
        except:
            server_logger.exception('Error cleaning client '+str(sock)+' input')
            self.client_remove(sock)
        if payload:
            self.clients[sock]['input_buffer']+=payload
            self.client_handle(sock)
        else:
            self.client_remove(sock)

    def clear_socket_outputs(self, sock):
        if sock not in list(self.clients.keys()):
            return
        try:
            payload=self.clients[sock]['output_buffer'][:BUFFER_SIZE]
            server_logger.debug('Sending package '+str(payload)+' to '+str(sock))
            bytes_sent=sock.send(payload.encode())
            server_logger.debug('Client: '+str(self.clients[sock])+' Message: '+str(self.clients[sock]['output_buffer'][:bytes_sent]))
            self.clients[sock]['output_buffer']=self.clients[sock]['output_buffer'][bytes_sent:]
        except Exception as e:
            server_logger.exception('Error cleaning client '+str(sock)+' output')
            self.client_remove(sock)

    # must check this link to understand (it's adapted from it)
    # https://steelkiwi.com/blog/working-tcp-sockets/
    def listen(self):
        server_logger.info('Now listening')
        while True:
            inputs = [self.sock] + list(self.clients.keys())
            outputs= [sock for sock in self.clients if len(self.clients[sock]['output_buffer'])>0]
            readable, writable, exceptional = select.select(inputs, outputs, inputs, 1000)
            server_logger.debug('Handling sockets inputs')
            for sock in readable:
                if sock is self.sock:
                    server_logger.debug('Handling self socket')
                    conn, addr = self.sock.accept()
                    self.client_accept(conn, addr)
                    conn.setblocking(0)
                else:
                    server_logger.debug('Handling client socket')
                    self.clear_socket_inputs(sock)
            server_logger.debug('Handling sockets outputs')
            for sock in writable:
                if sock in list(self.clients.keys()):
                    self.clear_socket_outputs(sock)
            server_logger.debug('Handling sockets with errors')
            for sock in exceptional:
                self.client_remove(sock)

    def game_check(self):
        self.croupier.missing_players(len(self.clients), self.clients)
        if len(self.clients.keys())==4:
            server_logger.debug('Game Started')
            self.game_start()
        if self.game_over:
            server_logger.debug('Game Finished')
            self.exit()

    def client_handle(self, client_socket):
        payload=self.clients[client_socket]['input_buffer']
        server_logger.debug(payload)
        self.clients[client_socket]['input_buffer']=''
        server_logger.debug(self.clients[client_socket])

    def game_start(self):
        server_logger.info('Game has started')
        self.croupier.update_players(self.clients)
        self.croupier.give_cards()

    def player_update(self, player_addr, update_type, data_to_update):
        if update_type=='signature':
            self.sec_clients_dict[player_addr].update({'signature': data_to_update['signature'], 'signature_method': data_to_update['sig_method']})
            security_logger.info('Player@'+player_addr[0]+' signature and signature method updated')
            security_logger.debug('Sig: '+data_to_update['signature']+' || Sig_M: '+data_to_update['sig_method'])
        elif update_type=='cipher_method':
            self.sec_clients_dict[player_addr].update({'cipher_methods': data_to_update['cipher_methods']})
            security_logger.info('Player@'+player_addr[0]+' cipher method updated')
            security_logger.debug('Ciphers: '+data_to_update['cipher_methods'])
        elif update_type=='RSA_KEY':
            self.sec_clients_dict[player_addr].update({'public_key': data_to_update['key']})
            security_logger.info('Player@'+player_addr[0]+' public key updated')
            security_logger.debug('Pub_Key: '+data_to_update['key'])
        else:
            server_logger(update_type+''+data_to_update)

    def pause(self):
        server_logger.info('Server paused, press CTRL+C again to exit')
        try:
            self.sock.close()
        except:
            server_logger.exception("Server Stopping")

        for client in self.clients:
            client.close()
        self.clients=[]
        time.sleep(5)

    def exit(self):
        server_logger.info('Exiting...')
        self.sock.close()
        sys.exit(0)

    def emergency_exit(self, e):
        server_logger.exception('Exception: '+str(e))
        self.sock.close()
        sys.exit(1)
