# logging
import logging
import coloredlogs

# server
import socket
import json
import sys
import traceback
import time 

# threading
from _thread import *

# keyboard
import keyboard

# player
from player import *
from client_crypto import *

# server logging
client_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
client_logger=logging.getLogger('CLIENT')
log_time=str(int(time.time()))
logging.basicConfig(filename='log/client_'+log_time+'.logs',
                            filemode='a',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)
BUFFER_SIZE=512*1024

class SecureClient:
    def __init__(self, host='0.0.0.0', port=8080, log_level='DEBUG'):
        # logging
        coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=client_log_colors)

        # client socket
        self.host = host 
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # game related
        self.player = None

    def register_player(self):
        try:
            username=input("Username: ")
            self.player=Player(username)
            payload={
                "operation":"client@register_player",
                "username":self.player.username
            }
            payload=json.dumps(payload)
            try:
                while payload:
                    to_send=payload[:BUFFER_SIZE]
                    self.sock.send(to_send.encode())
                    payload=payload[BUFFER_SIZE:]
            except OSError:
                self.delete_client(conn)
                server_logger.warning("Connection to server was closed")

        except KeyboardInterrupt:
            client_logger.info("Disconnected")
            payload={
                "operation":"client@disconnect_client"
            }
            payload=json.dumps(payload)
            self.sock.send(payload.encode())

    def connect(self):
        try:
            self.sock.connect((self.host, self.port))
            client_logger.info("Connected")
        except:
            traceback.print_exc()
            sys.exit(1)

    # debugs data if it has several payloads in it
    def debug_data(self, data):
        d = data.split(b'}{')
        if(len(d) > 1):
            for i in range(0, len(d)):
                if(i % 2 == 0):
                    d[i] += b'}'
                else:
                    d[i] = b'{' + d[i]
        return d

    def player_handler(self):
        self.register_player()
        while 1:
            try:
                try:
                    data=self.sock.recv(BUFFER_SIZE).decode('utf-8')
                except ConnectionResetError: # connection was reseted
                    self.delete_client(conn)
                    break
                except OSError: # connection was closed
                    self.delete_client(conn)
                    break
                if not data:
                    client_logger.error('Server closed')
                    break
                debugged = self.debug_data(data)
                for d in debugged:
                    payload = json.loads(d)
                    operation = payload["operation"]
                    if(operation == "server@require_action"):
                        # handle client trial to create table
                        if(payload["answer"] == "player@request_create_table"):
                            if(payload["success"]):
                                self.player.owner = True
                                self.player.in_table = True
                                self.player.table = payload["table"]
                                self.player.playing = False
                                client_logger.info("Player created table " + payload["table"] + " with success")
                                client_logger.info("Player is now waiting for table to be ready... ({}/4)".format(payload["nplayers"]))
                                client_logger.warning("To leave the table, please press CTRL-C")
                            else:
                                client_logger.warning("Player didn't create table " + str(payload["table"]))
                        # handle client trial to register
                        elif(payload["answer"] == "client@register_player"):
                            client_logger.info("Player registered")
                        # handle client trial to delete table
                        elif(payload["answer"] == "player@request_delete_table"):
                            if(payload["success"]):
                                self.player.owner = False
                                self.player.in_table = False
                                self.player.playing = False
                                self.player.table = payload["table"]
                                client_logger.info("Player deleted the table with success")
                            else:
                                client_logger.warning("Player didn't delete the table " + payload["table"])
                        # handle client trial to leave table
                        elif(payload["answer"] == "player@request_leave_table"):
                            if(payload["success"]):
                                self.player.in_table = False
                                self.player.table = payload["table"]
                                self.player.playing = False
                                self.player.owner = False
                                client_logger.info("Player left the table with success")
                            else:
                                client_logger.warning("Player didn't leave the table")
                        # handle client trial to join table
                        elif(payload["answer"] == "player@request_join_table"):
                            if(payload["success"]):
                                self.player.in_table = True
                                self.player.table = payload["table"]
                                self.player.owner = False
                                client_logger.info("Player joined table " + payload["table"] + " with success")
                                client_logger.info("Player is now waiting for table to be ready...({}/4)".format(payload["nplayers"]))
                                client_logger.warning("To leave the table, please press CTRL-C")
                            else:
                                client_logger.warning("Player didn't join the table")
                        # handle client trial to start game
                        elif(payload["answer"] == "player@game_start"):
                            self.player.in_table = True
                            self.player.table = payload["table"]
                            self.player.playing = True
                            client_logger.warning("Game started!")
                    # handle client trial to start game
                    elif(operation == "server@register_failed"):
                        client_logger.warning("Username already taken. Please choose another")
                        self.register_player()
                    elif(operation == "croupier@send_online_players"):
                        self.display_online_users(payload)
                    elif(operation == "croupier@send_online_tables"): 
                        self.display_online_tables(payload)
                    elif(operation == "croupier@table_deleted"): # inform that the table you were in was deleted
                        self.player.owner = False
                        self.player.in_table = False
                        self.player.table = None
                        self.player.playing = False
                        client_logger.warning("The table you were in was deleted. You may now join a new table")
                # after payload's loop
                if(self.player_not_in_table()):
                    self.menu_pre_game()
                else:
                    if(self.player.playing):
                        self.menu_in_game()
            except KeyboardInterrupt:
                if(self.player.in_table):
                    self.player.request_leave_table(self.player.table, self.sock)
                else:
                    break
        client_logger.info("Disconnected")
        if(self.player):
            self.player.request_leave_croupier(self.sock)
        client_logger.info("Player requested leaving croupier. Goodbye!")

    def run(self):
        self.connect()
        try:
            self.player_handler()
        except:
            traceback.print_exc()
            sys.exit(1)

    def display_online_tables(self, payload):
        print("Table\tOwner\t#Player\tLim\tReady")
        print("-------------------------------")
        for table_key in payload.keys():
            if(table_key != "operation"):
                table = payload[table_key]
                print("{}\t{}\t{}\t{}\t{}".format(table["table"], 
                                              table["owner"], 
                                              table["nplayers"], 
                                              table["limit"],
                                              table["ready"]))

    def display_online_users(self, payload):
        players = payload["players"]
        print("Player\tTable\tPoints\tStatus")
        print("----------------------------------")
        for player in players.keys():
            print("{}\t{}\t{}\t{}".format(players[player]["username"],
                                          players[player]["table"], 
                                          players[player]["points"], 
                                          players[player]["status"]))

    def player_not_in_table(self):
        return self.player.table == None and self.player.in_table == False and self.player.owner == False and self.player.playing == False

    def menu_pre_game(self):
        print("\n--------------   MENU   --------------")
        print("What do you want to do?")
        print("1 - Request online users")
        print("2 - Request online tables")
        print("3 - Request the creation of a table")
        print("4 - Request to join a table")
        option = 0
        while(option not in [1,2,3,4]):
            try:
                option = (int)(input("Option: "))
            except KeyboardInterrupt:
                if(self.player.in_table):
                    self.player.request_leave_table(self.player.table, self.sock)
                else:
                    break
            except ValueError:
                # in case client inputs letters
                client_logger.warning("Invalid option. Please choose a valid option")
        if(option == 1): # request online players
            self.player.request_online_users(self.sock)
        elif(option == 2): # request tables online
            self.player.request_tables_online(self.sock)
        elif(option == 3): # request the creation of a table
            table = input("Table name: ")
            self.player.request_create_table(table, self.sock)
        elif(option == 4): # request to join a table
            table = input("Table name: ")
            self.player.request_join_table(table, self.sock)
        else:
            pass

    def menu_in_game(self):
        print("Playing")
