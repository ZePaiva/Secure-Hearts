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
    def __init__(self, host='0.0.0.0', port=8080, log_level='INFO', tables=4):
        # logging
        coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=server_log_colors)
        self.tables=tables

        # server socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host,port))
        self.sock.listen(4*self.tables)
        server_logger.info('Server located @ HOST='+host+' | PORT='+str(port))
        server_logger.debug('server up, can support up to '+str(tables)+' and '+str(4*tables)+' players')

        # game related
        self.clients = {}
        self.croupier = Croupier()
        server_logger.debug('Croupier UP')

        # security related
        self.cryptography=CryptographyServer(log_level)
        server_logger.debug('Cryptography server UP')

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

    def get_conn_from_username(self, username):
        for connection in self.clients.keys():
            if(self.clients[connection]["username"] == username):
                break
        return connection

    def require_action(self, conn, answer="", success=1, mode="pre-game", table=None):
        payload = {
            "operation":"server@require_action",
            "answer":answer,
            "success":success,
            "mode":mode,
            "table":table
        }
        payload = json.dumps(payload)
        while payload:
            to_send=payload[:BUFFER_SIZE]
            conn.send(to_send.encode())
            payload=payload[BUFFER_SIZE:]

    def communication_thread(self, conn, addr):
        while 1:
            data = conn.recv(BUFFER_SIZE).decode()
            if not data:
                self.croupier.delete_player(conn)
                conn.close()
                server_logger.info("Disconnected " + self.clients[conn]["username"])
                break
            payload = json.loads(data)
            operation = payload["operation"]
            if(operation == "client@register_player"):
                server_logger.debug('Player trying to sign in')
                client,response=self.cryptography.sign_in(self.clients[conn]['address'], payload)
                if not client:
                    server_logger.warning('bad client tried to sign in')
                    payload=json.dumps(response)
                    while payload:
                        to_send=payload[:BUFFER_SIZE]
                        conn.send(to_send.encode())
                        payload=payload[BUFFER_SIZE:]
                    conn.close()
                    exit()
                self.clients[conn]["username"]=client['username']
                self.croupier.add_player(conn, addr, client['username'])
                server_logger.info("Player " + username + " joined the server")
                self.require_action(conn, answer=operation)
                server_logger.info("Sent a message to " + username + " to require an action")
            elif(operation == "player@request_online_users"):
                self.croupier.send_online_players(conn)
            elif(operation == "player@request_tables_online"):
                self.croupier.send_online_tables(conn)
            elif(operation == "player@request_create_table"):
                success = self.croupier.create_table(payload, conn)
                if success:
                    self.require_action(conn, answer=operation, success=success, table=payload["table"])
                else:
                    self.require_action(conn, answer=operation, success=success, table=None)
            elif(operation == "player@request_delete_table"):
                success = self.croupier.delete_table(payload, conn)
                if success:
                    self.require_action(conn, answer=operation, success=success, table=None)
                else:
                    self.require_action(conn, answer=operation, success=success, table=payload["table"])
            elif(operation == "player@request_join_table"):
                success = self.croupier.join_player_table(payload, conn)
                if(success == 0):
                    self.require_action(conn, answer=operation, success=success, table=None) 
                elif(success == 1):
                    self.require_action(conn, answer=operation, success=success, table=payload["table"]) 
                else:
                    connections = success
                    for connection in connections:
                        self.require_action(connection, answer=operation, success=1, mode="in-game", table=payload["table"])
                        server_logger.info("Sent information about the starting of the game to " + self.croupier.get_username(connection))
                    server_logger.info("Game started at table " + payload["table"])
            elif(operation == "player@request_leave_table"):
                success = self.croupier.remove_player_table(payload, conn)
                if success:
                    self.require_action(conn, answer=operation, success=success, table=None)
                else:
                    self.require_action(conn, answer=operation, success=success, table=payload["table"])

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
