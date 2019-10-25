import socket
import sys
import json
import time
import traceback
from player import *
from _thread import *
from utils import receive

host = '0.0.0.0'
port = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host,port))

# game related
player = Player()


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
