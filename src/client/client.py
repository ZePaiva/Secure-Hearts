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

# security
from paths import *
from cc_api import CC_API
from client_aux import *
from client_crypto import *
from utils.sec_utils import *
from utils.certificates_utils import *
from cryptography.hazmat.primitives import hashes

# server logging
client_logger=logging.getLogger('CLIENT')
log_time=str(int(time.time()))
logging.basicConfig(filename='log/client_'+log_time+'.logs',
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)
BUFFER_SIZE=512*1024

class SecureClient:
    def __init__(self, host='0.0.0.0', port=8080, log_level='ERROR'):
        # client socket
        self.host = host 
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.log_level=log_level
        client_logger.setLevel(log_level)

        # game related
        self.player = None
        self.uuid=None
        self.username=None

        # security related
        self.cc_api=None
        self.cert=None
        self.cc_num=None
        self.security_handler=None


    def register_player(self):
        try:
            client_logger.debug('logging new client, process started')
            print('+------------------------+')
            print('|       CONNECTING       |')
            print('+------------------------+')
            # pick if using cc
            cli=YesNo(prompt='Will you be using CC? ')
            cc_on=None
            while cc_on is None:
                try:
                    cc_on=cli.launch()
                except:
                    print()
                    pass
            client_logger.debug('CC - '+str(cc_on))
            # in case of not using cc
            if not cc_on:
                self.cc_api=None
                client_logger.debug('no cc')
                cli=Input('Username: ')
                self.username=cli.launch()
                client_logger.debug('username: '+str(self.username))
                self.cc_cert=generate_certificate(self.username)[0]
                client_logger.debug('cert: '+str(self.cc_cert))
            # in case of using cc
            else:
                try:
                    self.cc_api=CC_API()
                    client_logger.debug('cc api UP')
                    self.cc_cert=self.cc_api.get_pubKey_cert()
                    client_logger.debug('cert: '+str(self.cc_cert))
                    self.username=self.cc_api.get_citizen_card_info()['name']
                    client_logger.debug('username: '+str(self.username))
                    self.cc_num=self.cc_api.get_citizen_card_info()['serialnumber']
                    client_logger.debug('CC ID: '+str(self.cc_num))
                except IndexError as e:
                    client_logger.warning('PCSCD not activated')
                    print(colored("Service pcscd not active, please run the command sudo systemctl start pcscd.service if using systemctl", 'red'))
                    print(colored("Retry after using said command", 'red'))
                    os._exit(0)
                except PyKCS11.PyKCS11Error as e:
                    client_logger.warning('CARD NOT INSERTED')
                    print(colored("Insert pt e-id and retry", 'red'))
                    print(colored("If it is already inserted take it out and put in again, might work", 'red'))
                    os._exit(0)
            # pick sec_spec
            cipher_methods=None
            while not cipher_methods:
                try:
                    cipher_methods=pick_ciphers(cc_on)
                    client_logger.debug('cipher_methods: '+str(cipher_methods))
                except Exception as e:
                    print()
                    pass
            # creating player
            self.player=Player(self.username)
            client_logger.debug('Player UP')
            # checking for keys
            keys_dir=os.path.join(KEYS_DIR,str(self.username))
            client_logger.debug('Loading keys')
            if not os.path.exists(keys_dir):
                # handling creation and storage of keys
                os.makedirs(keys_dir)
                rsa_private_key=generate_rsa()
                write_private_key(os.path.join(keys_dir,'prv_rsa'), rsa_private_key)
                client_logger.debug('stored private key @ '+keys_dir)
                write_public_key(os.path.join(keys_dir,'pub_rsa'), rsa_private_key.public_key())
                client_logger.debug('stored public key @ '+keys_dir)
            else:
                rsa_private_key=read_private_key(os.path.join(keys_dir,'prv_rsa'))
                client_logger.debug('loaded private key from '+keys_dir)
            server_key=read_public_key(os.path.join(SERVER_KEY,'pub_rsa'))
            # create secure client
            self.security_handler=CryptographyClient(self.log_level,
                                                    rsa_private_key, rsa_private_key.public_key(),
                                                    server_key, cipher_methods, 
                                                    log_time,
                                                    cc_on, self.cc_cert, self.cc_api
                                                    )
            first_package=json.dumps(
                self.security_handler.secure_init_message(self.username)
            )
            try:
                while first_package:
                    to_send=first_package[:BUFFER_SIZE]
                    self.sock.send(to_send.encode())
                    first_package=first_package[BUFFER_SIZE:]
            except OSError:
                self.delete_client(conn)
                client_logger.warning("Connection to server was closed")

        except KeyboardInterrupt:
            client_logger.info("Disconnected")
            payload={
                "operation":"client@disconnect_client"
            }
            while payload:
                to_send=payload[:BUFFER_SIZE]
                self.sock.send(to_send.encode())
                payload=payload[BUFFER_SIZE:]
            payload=json.dumps(payload)
            self.sock.send(payload.encode())
            self.exit()

    def connect(self):
        try:
            self.sock.connect((self.host, self.port))
            client_logger.info("Connected")
        except:
            traceback.print_exc()
            sys.exit(1)

    # debugs data if it has several payloads in it
    def debug_data(self, data):
        print(data)
        d = data.split('}{')
        if(len(d) > 1):
            for i in range(0, len(d)):
                if(i % 2 == 0):
                    d[i] += '}'
                else:
                    d[i] = '{' + d[i]
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
                        payload=self.security_handler.server_parse_security(payload)
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
                    self.exit()
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
        print("0 - Exit game")
        print("1 - Request online users")
        print("2 - Request online tables")
        print("3 - Request the creation of a table")
        print("4 - Request to join a table")
        option = None
        while(option not in [0,1,2,3,4]):
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
        elif(option == 0): # request to join a table
            print('Exiting...')
            self.exit()
        else:
            pass

    def menu_in_game(self):
        print("Playing")

    def pause(self):
        client_logger.info('Server paused, press CTRL+C again to exit')
        try:
            self.sock.close()
        except:
            client_logger.exception("Server Stopping")
        for client in self.clients:
            client.close()
        self.clients=[]
        time.sleep(5)

    def exit(self):
        client_logger.info('Exiting...')
        self.sock.close()
        os._exit(0)

    def emergency_exit(self, exception):
        client_logger.critical('An Exception caused an emergency exit')
        client_logger.exception(exception)
        os._exit(0)
