import socket
import sys
from _thread import *
from hearts import *
from croupier import *
import json
import traceback


host = '0.0.0.0'
port = 8080

clients = []

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    s.bind((host,port))
    print('socket binding to ' + host + ':' + str(port))
except Exception as e:
    print(e)
    sys.exit(1)

s.listen(4) # listens to up to 4 clients
print('Waiting for 4 clients')

# game related
croup = Croupier(deck=cards)
current_player_idx = None
cards_on_table = []
current_suit = ''


def clientthread():
    global clients
    global croup
    global current_player_idx
    global cards_on_table
    global current_suit
    conn, addr = clients[-1]
    identification = addr[0] + ":" + str(addr[1])
    while 1:
        data = conn.recv(1024)
        if not data:
            break
        try:
            payload = json.loads(data.decode())
            operation = payload['operation']
            print(payload)
            if operation == "player@has_two_of_clubs":
                if payload["has_2C"]:
                    croup.give_order((conn, addr))
                    current_player_idx = 0
            elif operation == "player@is_ready":
                print('Current player idx: ', current_player_idx)
                if payload["order"] == current_player_idx:
                    croup.demand_play_card(current_player_idx)
            elif operation == "player@play":
                if croup.round==0 and current_player_idx==0 and payload['card']!='2C':
                    croup.demand_play_card(current_player_idx, 'must start with that play')
                elif not croup.heart_brake and current_player_idx==0 and 'H' in payload['card']:
                    croup.demand_play_card(current_player_idx, 'hearts not broken')
                elif payload["order"] == current_player_idx:
                    if current_player_idx == 0:
                        current_suit = payload["card"][-1]

                    croup.round+=1
                    if 'H' in payload['card']:
                        croup.heart_brake=True
                    cards_on_table.append((payload["order"], payload["card"]))
                    print(cards_on_table)

                    if current_player_idx == len(clients)-1:
                        # get the loser of the table
                        cards_for_loser = [c[1] for c in cards_on_table.copy()]
                        # from hearts
                        hc = get_higher_card(cards_for_loser, current_suit)
                        loser_idx = 0
                        for o,c in cards_on_table:
                            if c == hc:
                                loser_idx = o
                                break

                        current_suit = ''
                        current_player_idx = 0
                        cards_on_table = []

                        croup.give_cards_to_loser(loser_idx, cards_for_loser)

                    else:
                        current_player_idx = (current_player_idx + 1) % 4
                        croup.demand_play_card(
                            current_idx=current_player_idx, 
                            table=cards_on_table
                        )

        except Exception as e:
            print(e)
            traceback.print_exc()
            print('Not json')
            print(data.decode())
        
    conn.close()

while 1:
    try:
        conn, addr = s.accept()
        clients.append((conn, addr))
        print('Connected with ' + addr[0] + ":" + str(addr[1]))
        croup.missing_players(len(clients), clients)
        start_new_thread(clientthread, ())
        if len(clients)==4:
            croup.update_players(clients)
            croup.give_cards()

    except Exception as e:
        print(e)
        s.close()
        print('Socket closed')
        print('Exiting')
        sys.exit(1)

