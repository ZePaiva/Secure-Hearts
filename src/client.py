import socket
import sys
from _thread import *
import json
import time
from player import *

host = '0.0.0.0'
port = 8080

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(s.connect((host,port)))

# game related
player = Player()

def datathread(s):
    while 1:
        data = s.recv(1024)
        if not data:
            break
        try:
            payload = json.loads(data.decode())
            print(payload)
            operation = payload['operation']
            global player
            if operation == "croupier@give_cards":
                player.update_hand(payload['hand'])
                player.update_id(payload['address'])
                player.communicate_has_2C(s)
            elif operation == "croupier@give_order_of_player":
                order = payload["order"]
                player.update_order(order)
                player.communicate_is_ready(s)
            elif operation == "croupier@play_card":
                if payload["order"] == player.order:
                    player.play(s)
            elif operation == "croupier@give_cards_to_loser":
                if player.order == payload["loser_order"]:
                    player.update_used_cards(payload["cards"])
                    player.update_points(payload["points"])

        except Exception as e:
            # not a json packet
            print(e)
            print(data.decode())

try:
    start_new_thread(datathread, (s,))
    # keep the client alive (mainthread)
    while 1:
        time.sleep(0.001)
except Exception as e:
    print(e)
    sys.exit(1)

s.close()
