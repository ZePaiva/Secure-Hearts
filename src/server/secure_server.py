# to not debug with prints
import logging
import coloredlogs

# to work
import socket
import sys
import json
import traceback
import uuid
from pprint import pprint

from _thread import *

# work bibs
from hearts import *
from croupier import *
from utils.server_utils import *
from utils.server_utils import *

# logging utils
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s' )
server_logger=logging.getLogger('SERVER')
security_logger=logging.getLogger('SECURITY')
server_logger.setLevel(logging.DEBUG)
security_logger.setLevel(logging.DEBUG)
print(server_logger)
print(security_logger)
server_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
coloredlogs.install(level='DEBUG', fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=server_log_colors, logger=server_logger )
print(server_logger)
print(security_logger)
# socket utils
host='0.0.0.0'
port=8080

class SecureServer(object):
    def __init__(self):
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.croupier=Croupier(deck=cards)
        self.current_player_idx=None
        self.cards_on_table=[]
        self.current_suite=None
        self.game_over=False
        self.clients=[]
        self.previous_plays=[]
        self.sec_clients_dict={}

    def start_and_listen(self):
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((host,port))
            self.sock.listen()
            server_logger.info('Server located @ HOST='+host+' | PORT='+str(port))
        except Exception as e:
            server_logger.error(e)
            sys.exit(1)
        server_logger.info('Awaiting players')

    def client_handler(self):
        try:
            conn, addr =self.clients[-1]
            data=receive(conn)
        except Exception as e:
            server_logger.error('Lost connection to client')
            self.clients=self.clients[1:3]
        try:
            payload=json.loads(data)
            server_logger.info('Server received packet '+str(payload))
            oper=payload['operation']
            # TODO: sign in proccess and authentication
            if oper=='player@sign_in':
                self.player_sign_in(addr,payload)
                server_logger.info('Player@'+addr[0]+' signed in with ID ')
                security_logger.info('Player public key stored')
                server_logger.debug('Updated players: '+str(self.sec_clients_dict))
            # TODO: passage of cards between players
            elif oper=='player@requesting_cards':
                server_logger.info('Player@'+addr[0]+' requested '+payload['card_amount']+ ' cards')
            # TODO: passage of cards between players and pick methods (?)
            elif oper=='player@sign_cards':
                server_logger.debug('Player@'+addr[0]+' signature received')
                security_logger.debug('Player@'+addr[0]+' signature received and stored')
                security_logger.info('Player@'+addr[0]+' signature method : \033[1;32m'+payload['sig_method'])
                self.player_update(addr, 'signature', {'signature': payload['signature'], 'signature_method': payload['sig_method']})
            # TODO: authentication
            elif oper=='player@has_two_of_clubs':
                self.croupier.without_suits[payload['player_id']] = []
                if payload['has_2C']:
                    server_logger.info('Player '+str(addr[0])+':'+str(addr[1])+' has 2♣ (two of clubs)')
                    self.current_player_idx=0
                    self.croupier.give_order((conn, addr))
            # TODO: ciphering of communications
            elif oper=='player@is_ready':
                server_logger.info('Player '+str(self.current_player_idx)+' is ready')
                if payload['order'] == self.current_player_idx:
                    self.croupier.demand_play_card(self.current_player_idx)
            # TODO: ciphering of communications
            elif oper=='player@play':
                if self.croupier.round==0 and self.current_player_idx==0 and payload['card']!='2C':
                    server_logger.warning('Player '+str(self.current_player_idx)+' played INVALID CARD:'+payload['card'])
            # TODO: Reports on player side
            elif oper=='player@report_bad_play':
                server_logger.info('Player@'+addr[0]+' reported '+payload['reported_player']+ ' play')
            # TODO: Get all cards from player and signature
            elif oper=='player@show_cards':
                server_logger.info('Player@'+addr[0]+' showed his cards')
            # TODO: Nothing, this if is just for shits and giggles
            else:
                server_logger.debug('Nothing happened, here\'s the payload:'+str(payload))
        except TypeError as e:
            server_logger.exception('Error: Received empty packet')
        except KeyError as e:
            server_logger.exception('Error with key: '+str(e))

    def client_accepter(self):
        try:
            conn,addr=self.sock.accept()
            self.clients.append((conn,addr))
            server_logger.info('Connection established with HOST='+str(addr[0])+' PORT='+str(addr[1]))
            self.croupier.missing_players(len(self.clients), self.clients)
            start_new_thread(self.client_handler, ())
            if len(self.clients)==4:
                self.game_start()
            if self.game_over:
                server_logger.info('Game has finished, exiting')
                self.sock.close()
                sys.exit(0)
        except Exception as e:
            server_logger.error('Error: '+str(e))
            self.sock.close()
            traceback.print_exc()
            sys.exit(1)

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

    def player_sign_in(self, player_addr, payload_day_0):
        try:
            server_logger.debug('playr_addr: '+str(player_addr))
            server_logger.debug('playr_payload: '+str(payload_day_0))
            self.sec_clients_dict.update({player_addr: 
                                          {
                                            'name': payload_day_0['name'],
                                            'public_key': payload_day_0['key'],
                                            'signature': payload_day_0['signature'],
                                            'cipher_methods': payload_day_0['cipher_methods'],
                                            'signature_method': payload_day_0['sig_method']
                                          }})
            server_logger.debug('payload: '+str(payload_day_0))
        except Exception as e:
            server_logger.exception('Exception '+e+' @ player_sign_in')

sec_serv=SecureServer()
sec_serv.start_and_listen()
while 1:
    sec_serv.client_accepter()

