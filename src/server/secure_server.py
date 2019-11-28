# to not debug with prints
import logging
import coloredlogs

# to work
import socket
import sys
import json
import traceback
from pprint import pprint

from _thread import *

# work bibs
from hearts import *
from croupier import *
from utils.server_utils import *
from utils.server_utils import *

# logging utils
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
coloredlogs.install(fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=log_colors)
server_logger=logging.getLogger('SERVER')
server_logger.setLevel('INFO')
security_logger=logging.getLogger('SECURITY')
security_logger.setLevel('INFO')

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
            if oper=='player@has_two_of_clubs':
                self.croupier.without_suits[payload['player_id']] = []
                if payload['has_2C']:
                    server_logger.info('Player '+str(addr[0])+':'+str(addr[1])+' has 2♣ (two of clubs)')
                    self.current_player_idx=0
                    self.croupier.give_order((conn, addr))
            elif oper=='player@is_ready':
                server_logger.info('Player '+str(self.current_player_idx)+' is ready')
                if payload['order'] == self.current_player_idx:
                    self.croupier.demand_play_card(self.current_player_idx)
            elif oper=='player@play':
                if self.croupier.round==0 and self.current_player_idx==0 and payload['card']!='2C':
                    server_logger.warning('Player '+str(self.current_player_idx)+' played INVALID CARD:'+payload['card'])
            else:
                server_logger.debug('Nothing happened, here\'s the payload:'+str(payload))
        except TypeError:
            server_logger.error('Error: Received empty packet')
        except Exception as e:
            server_logger.error('Error: '+str(e))

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

sec_serv=SecureServer()
sec_serv.start_and_listen()
while 1:
    sec_serv.client_accepter()

