# logging
import logging
import coloredlogs

# server
import socket
import json
import sys
import traceback

# threading
from _thread import *

# croupier
from croupier import Croupier

# cryptography 
from server_crypto import *
from utils.server_utils import *
from utils.server_utils import *

# server logging
server_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
server_logger=logging.getLogger('SERVER')

BUFFER_SIZE=512*1024

class SecureServer(object):
    def __init__(self, host='0.0.0.0', port=8080, log_level='DEBUG', tables=4):
        # logging
        coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=server_log_colors)
        self.tables=tables
        # server socket
        print("ola")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("ola")
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("ola")
        self.sock.bind((host,port))
        print("ola")
        self.sock.listen(4*self.tables)
        server_logger.info('Server located @ HOST='+host+' | PORT='+str(port))
        # game related
        self.clients = {}
        self.croupier = Croupier()
        server_logger.debug('Croupier UP')
        # security related
        self.cryptography=CryptographyServer(log_level)
        server_logger.debug('Cryptography UP')

    def accept_client(self):
        try:
            conn, addr = self.sock.accept()
            if conn in self.clients:
                server_logger.warning('Client %s already exists', conn)
                return None
            self.clients[conn] = {
                "address":addr,
                "conn":conn
            }
            server_logger.info("Client " + str(conn) + " accepted.")
            return conn, addr
        except Exception as e:
            return None

    def send_payload(self, payload, conn):
        payload=json.dumps(payload)
        while payload:
            to_send=payload[:BUFFER_SIZE]
            conn.send(to_send.encode('utf-8'))
            payload=payload[BUFFER_SIZE:]

    def receive_payload(self, conn):
        res=''
        while True:
            req=conn.recv(BUFFER_SIZE)
            res+=req.decode('utf-8')
            try:
                r=json.loads(res)
                server_logger.debug(str(r))
                return r
            except:
                continue

    def get_conn_from_username(self, username):
        for connection in self.clients.keys():
            if self.clients[connection]["username"]==username:
                break
        return connection

    def require_action(self, conn, answer="", success=1, mode="pre-game", table=None, nplayers=0, username=None):
        payload = {
            "operation":"server@require_action",
            "answer":answer,
            "success":success,
            "mode":mode,
            "table":table,
            "nplayers":nplayers,
            "username":username
        }
        try:
            payload=self.cryptography.secure_package(self.clients[conn]['address'], payload, 'server@require_action',update_public_key=True)
        except KeyError:
            server_logger.warning("Message not encapsulated")
        try:
            self.send_payload(payload, conn)
        except OSError:
            self.delete_client(conn)
            server_logger.warning("Connection was closed")

    def delete_client(self, conn):
        try:
            self.croupier.delete_player(conn)
        except UnboundLocalError:
            pass
        # username = self.croupier.get_username(conn)
        conn.close()
        # server_logger.info("Disconnected " + str(username))
        server_logger.info("Disconnected " + str(conn))

    def communication_thread(self, conn, addr):
        while 1:
            try:
                payload=self.receive_payload(conn)
            except ConnectionResetError: # connection was reseted
                self.delete_client(conn)
                break
            except OSError: # connection was closed
                self.delete_client(conn)
                break
            # client dead
            if not payload:
                self.delete_client(conn)
                break
            # parsing data
            operation = payload["operation"]
            # MUST BE SAFE - handle client connecting
            if operation=="client@register_player":
                client,response=self.cryptography.sign_in(self.clients[conn]['address'], payload)
                # client failed to pass security to log in
                if not client:
                    server_logger.warning('bad client tried to sign in')
                    server_logger.debug(response)
                    response['operation']='server@register_failed'
                    self.send_payload(payload, conn)
                    conn.close()
                    os._exit(0)
                # client passed security
                success=self.croupier.add_player(conn, addr, client['username'])
                # client was succesffully added to croupier
                if success:
                    self.clients[conn]["username"]=client['username']
                    self.require_action(conn, answer="client@register_player", success=success, username=client['username'])
                    server_logger.info("Requested for cryptography data from client")                    
                # or not
                else:
                    payload = {
                        "operation":"server@register_failed",
                        "error":"error@username_taken"
                    }
                    self.send_payload(payload, conn)
                    server_logger.warning("Informed client that username is already taken")  
            # CAN BE UNSAFE - handle client disconnecting
            elif operation=="client@disconnect_client":
                self.delete_client(conn)
                break
            # CAN BE UNSAFE - handle client asking online users
            elif operation=="player@request_online_users":
                self.send_payload(self.croupier.send_online_players(conn), conn)
            # CAN BE UNSAFE - handle client asking possible tables
            elif operation=="player@request_tables_online":
                self.send_payload(self.croupier.send_online_tables(conn), conn)
            # CAN BE UNSAFE - handle client asking to create table
            elif operation=="player@request_create_table":
                success = self.croupier.create_table(payload, conn)
                if success:
                    nplayers = self.croupier.tables[payload["table"]]["nplayers"]
                    self.require_action(conn, answer=operation, success=success, table=payload["table"], nplayers=nplayers)
                else:
                    self.require_action(conn, answer=operation, success=success, table=None)
            # CAN BE UNSAFE - handle client asking to delete table
            elif operation=="player@request_delete_table":
                success = self.croupier.delete_table(payload, conn)
                if success:
                    self.require_action(conn, answer=operation, success=success, table=None)
                else:
                    self.require_action(conn, answer=operation, success=success, table=payload["table"])
            # CAN BE UNSAFE SOMETIMES - handling client asking to join table
            elif operation=="player@request_join_table":
                success = self.croupier.join_player_table(payload, conn)
                if success==0:
                    self.require_action(conn, answer=operation, success=success, table=None) 
                elif success==1:
                    nplayers = self.croupier.tables[payload["table"]]["nplayers"]
                    self.require_action(conn, answer=operation, success=success, table=payload["table"], nplayers=nplayers) 
                else:
                    # game has started
                    connections = success
                    nplayers = self.croupier.tables[payload["table"]]["nplayers"]
                    # send information about game starting
                    for connection in connections:
                        self.require_action(connection, answer="player@game_start", success=1, mode="in-game", table=payload["table"], nplayers=nplayers)
                        server_logger.info("Sent information about the starting of the game to " + self.croupier.get_username(connection))
                    # send cards to the first player in the queue (table's order)
                    player_order = self.croupier.tables[payload["table"]]["order"]
                    connection = self.croupier.players_conn[player_order[0]] 
                    # increment distribution idx
                    self.croupier.tables[payload["table"]]["cards_dist_idx"] += 1
                    print("PAYLOAD TABLE: " + str(payload["table"]))
                    payload=self.croupier.give_shuffled_cards(payload["table"], connection)
                    # TODO cipher cards
                    self.send_payload(
                        self.cryptography.secure_package(
                            payload
                        ),
                        conn
                    )
            # CAN BE UNSAFE - handling client asking to leave table
            elif operation=="player@request_leave_table":
                success = self.croupier.remove_player_table(payload, conn)
                if success:
                    self.require_action(conn, answer=operation, success=success, table=None)
                else:
                    self.require_action(conn, answer=operation, success=success, table=payload["table"])
            # CAN BE UNSAFE - handling client asking to leave game
            elif operation=="player@request_leave_croupier":
                self.delete_client(conn)
                break
            # MUST BE SAFE - player returns the shuffled cards
            elif operation=="player@return_shuffled_cards":
                idx = self.croupier.tables[payload["table"]]["cards_dist_idx"]
                if(idx != 0): # if distribution isn't complete
                    player_order = self.croupier.tables[payload["table"]]["order"]
                    connection = self.croupier.players_conn[player_order[idx]]
                    payload=self.croupier.give_shuffled_cards(payload["table"], connection)
                    # cipher/decipher cards
                    self.send_payload(
                        self.cryptography.secure_package(payload),
                        conn
                    )
                    # update table order idx
                    self.croupier.tables[payload["table"]]["cards_dist_idx"] = (idx + 1) % 4
                else:
                    server_logger.warning("DISTRIBUTION OF DECKS COMPLETED")

    def run(self):
        while True:
            try:
                conn, addr = self.accept_client()
                start_new_thread(self.communication_thread,(conn, addr, ))
            except Exception as e:
                server_logger.exception(e)

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

    def emergency_exit(self, exception):
        server_logger.critical('An Exception caused an emergency exit')
        server_logger.exception(exception)
        sys.exit(1)
