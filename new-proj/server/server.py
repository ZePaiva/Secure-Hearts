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


# server logging
server_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
server_logger=logging.getLogger('SERVER')

class Server:
	def __init__(self, log_level='DEBUG'):
		# logging
		coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=server_log_colors)

		# host and port for pre-game socket
		self.host = '0.0.0.0' 
		self.port = 8080

		# server socket
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((self.host, self.port))
		self.sock.listen(16)
		
		# game related
		self.clients = {}
		self.croupier = Croupier()

	def accept_client(self):
		try:
			conn, addr = self.sock.accept()
			self.clients[conn] = {
				"address":addr,
				"conn":conn,
				"ECDH private":"",
				"ECDH public":"",
				"RSA private":"",
				"RSA public":""
			}
			server_logger.info("Client " + str(conn) + " accepted.")
			return conn, addr
		except Exception as e:
			traceback.print_exc()
			sys.exit(1)

	def get_conn_from_username(self, username):
		for connection in self.clients.keys():
			if(self.clients[connection]["username"] == username):
				break

		return connection  

	def require_action(self, conn, answer="", success=1, mode="pre-game", table=None, nplayers=-1):
		payload = {
			"operation":"server@require_action",
			"answer":answer,
			"success":success,
			"mode":mode,
			"table":table,
			"nplayers":nplayers
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())


	def delete_client(self, conn):
		self.croupier.delete_player(conn)
		conn.close()
		server_logger.info("Disconnected " + self.clients[conn]["username"])

	def communication_thread(self, conn, addr):
		while 1:
			try:
				data = conn.recv(1024).decode()
			except ConnectionResetError:
				self.delete_client(conn)
				break

			if not data:
				self.delete_client(conn)
				break
			
			payload = json.loads(data)
			operation = payload["operation"]
			
			if(operation == "client@register_player"):
				username = payload["username"]
				self.clients[conn]["username"] = username
				self.croupier.add_player(conn, addr, username)
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
					nplayers = self.croupier.tables[payload["table"]]["nplayers"]
					self.require_action(conn, answer=operation, success=success, table=payload["table"], nplayers=nplayers)
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
					nplayers = self.croupier.tables[payload["table"]]["nplayers"]
					self.require_action(conn, answer=operation, success=success, table=payload["table"], nplayers=nplayers) 
				else:
					connections = success
					nplayers = self.croupier.tables[payload["table"]]["nplayers"]
					for connection in connections:
						self.require_action(connection, answer="player@game_start", success=1, mode="in-game", table=payload["table"], nplayers=nplayers)
						server_logger.info("Sent information about the starting of the game to " + self.croupier.get_username(connection))

					server_logger.info("Game started at table " + payload["table"])

			elif(operation == "player@request_leave_table"):
				success = self.croupier.remove_player_table(payload, conn)

				if success:
					self.require_action(conn, answer=operation, success=success, table=None)
				else:
					self.require_action(conn, answer=operation, success=success, table=payload["table"])

			elif(operation == "player@request_leave_croupier"):
				self.delete_client(conn)
				break




	def run(self):
		try:
			while 1:
				try:
					conn, addr = self.accept_client()
				except KeyboardInterrupt:
					server_logger.info("Server shutdown")
					break
				start_new_thread(self.communication_thread,(conn, addr, ))
		except:
			traceback.print_exc()
			sys.exit(1)

server = Server()
server_logger.info("Waiting for clients...")

server.run()
