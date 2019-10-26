# to not debug with prints
import logging

# to work
import socket
import sys
import json
import traceback

from _thread import *

# work bibs
from hearts import *
from croupier import *
from utils import *

# logging utils
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
        self.current_player_idx=0
        self.cards_on_table=[]
        self.current_suite=None
        self.game_end=None

    def start_and_listen(self):
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((host,port))
            server_logger.info('Server connecetd HOST='+host+' | PORT='+str(port))
        except Exception as e:
            server_logger.error(e)
            sys.exit(1)
        self.sock.levelname(4)
        server_logger.info('Awaiting players')

    def client_handler(self):
        try:
            payload=json.loads




