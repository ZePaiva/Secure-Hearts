# basic stuff
import sys
import json
import time
import traceback
from _thread import *
from socket import *

# game stuff
from player import *
from utils import receive

# to not debug with prints
import logging

# pretty up stuff
from bullet import *
from termcolor import colored

# server stuff
BUFFER_SIZE=512*1024

# client logging
client_logger=logging.getLogger('CLIENT')
fh_log=logging.fileHandler('log/client_'+str(int(time.time()))+'.logs')
fh_log.setLevel(logging.DEBUG)
fh_log.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
client_logger.addHandler(fh_log)

# game related
player = Player()

class Client(object):
    def __init__(self, host='0.0.0.0', port=8080):
        # client stuff
        self.sock=socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.username=''

        # client security stuff
        self.uuid=None
        self.RSA_key=None
        self.cipher_methods=None

        # CC stuff
        self.cc_cert=None
        self.cc_pin=None

        self.connect()

    def send(self, payload, server_res=True):
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

    def connect(self):
        print('##########################')
        print('#          LOGIN         #')
        print('##########################')
        print("# INSERT CC, ELSE WON'T  #")
        print("#           WORK         #")
        print('##########################')
        
        # get cc certificate and put it on self.cc_cert
        #

def datathread(s):
    global player
    while 1:
        # data = s.recv(1024)
        data = receive(s)
        if not data:
            break
        try:
            payload = json.loads(data)
            print(payload)
            operation = payload['operation']
            # global player
            if operation == "croupier@give_cards":
                while player.hand == []:
                    player.update_hand(payload['hand'])
                player.update_id(payload['address'])
                player.communicate_has_2C(s)
            elif operation == "croupier@give_order_of_player":
                order = payload["order"]
                player.update_order(order)
                player.communicate_is_ready(s)
            elif operation == "croupier@play_card":
                print("Current table: " + str(payload["table"]))
                if payload["order"] == player.order:
                    player.play(s)
            elif operation == "croupier@give_cards_to_loser":
                if player.order == payload["loser_order"]:
                    player.update_used_cards(payload["cards"])
                    player.update_points(payload["points"])

        except Exception as e:
            # not a json packet
            print('Exception in Client.py at datathread')
            print(e)
            traceback.print_exc()
            print(data)

try:
    start_new_thread(datathread, (s,))
    # keep the client alive (mainthread)
    while 1:
        time.sleep(1)
except Exception as e:
    print('Exception in client.py at mainthread')
    print(e)
    traceback.print_exc()
    sys.exit(1)

s.close()
