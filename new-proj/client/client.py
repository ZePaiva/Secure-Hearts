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

# player
from player import *

# server logging
client_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
client_logger=logging.getLogger('CLIENT')


class Client:
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
		username = input("Username: ")
		self.player = Player(username)
		
		payload = {
			"operation":"client@register_player",
			"username":self.player.username
		}

		payload = json.dumps(payload)
		self.sock.send(payload.encode())
		client_logger.info("Register player")


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
			data = self.sock.recv(1024)
			if not data:
				break

			debugged = self.debug_data(data)
			for d in debugged:
				payload = json.loads(d)
				operation = payload["operation"]

				if(operation == "server@require_action"):
					if(payload["answer"] == "player@request_create_table"):
						if(payload["success"]):
							self.player.owner = True
							self.player.in_table = True
							self.player.table = payload["table"]
							self.player.playing = False
							client_logger.info("Player created table " + payload["table"] + " with success")
						else:
							client_logger.warning("Player didn't create table " + payload["table"])

						if not self.player.playing:
							self.menu_pre_game()
						else:
							self.menu_in_game()

					elif(payload["answer"] == "client@register_player"):
						self.menu_pre_game()
						client_logger.info("Player registered")

					elif(payload["answer"] == "player@request_delete_table"):
						if(payload["success"]):
							self.player.owner = False
							self.player.in_table = False
							self.player.playing = False
							self.player.table = payload["table"]
							client_logger.info("Player deleted the table with success")
						else:
							client_logger.warning("Player didn't delete the table " + payload["table"])
						
						if not self.player.playing:
							self.menu_pre_game()
						else:
							self.menu_in_game()
						
					elif(payload["answer"] == "player@request_leave_table"):
						if(payload["success"]):
							self.player.in_table = False
							self.player.table = payload["table"]
							self.player.playing = False
							self.player.owner = False
							client_logger.info("Player left the table with success")
						else:
							client_logger.warning("Player didn't leave the table")

						if not self.player.playing:
							self.menu_pre_game()
						else:
							self.menu_in_game()

					elif(payload["answer"] == "player@request_join_table"):
						if(payload["success"]):
							self.player.in_table = True
							self.player.table = payload["table"]
							self.player.owner = False
							client_logger.info("Player joined table " + payload["table"] + " with success")

							if(payload["mode"] == "in-game"):
								self.player.playing = True
								client_logger.info("Player started playing Hearts at table " + self.player.table)
						else:
							client_logger.warning("Player didn't join the table")

						if not self.player.playing:
							self.menu_pre_game()
						else:
							self.menu_in_game()
				
				elif(operation == "croupier@send_online_players"):
					self.display_online_users(payload)
					if not self.player.playing:
						self.menu_pre_game()
					else:
						self.menu_in_game()

				elif(operation == "croupier@send_online_tables"): 
					self.display_online_tables(payload)
					if not self.player.playing:
						self.menu_pre_game()
					else:
						self.menu_in_game()

				elif(operation == "croupier@table_deleted"): # inform that the table you were in was deleted
					self.player.owner = False
					self.player.in_table = False
					self.player.table = None
					self.player.playing = False
					client_logger.warning("The table you were in was deleted. You may now join a new table")
					


		client_logger.info("Disconnected")
		self.sock.close()
		sys.exit(0)


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
		print("4 - Request the deletion of your table")
		print("5 - Request to join a table")
		print("6 - Request to leave the table")
		option = (int)(input("Option: "))

		
		if(option == 1): # request online players
			self.player.request_online_users(self.sock)
		
		elif(option == 2): # request tables online
			self.player.request_tables_online(self.sock)
		
		elif(option == 3): # create a table
			if(self.player_not_in_table()):
				table = input("Table name: ")
				self.player.request_create_table(table, self.sock)
			else:
				client_logger.warning("Player already in table " + self.player.table + ". Table not created")
				self.menu_pre_game()

		elif(option == 4): # request the deletion of a table
			if(self.player_not_in_table()):
				client_logger.warning("Player is not the owner of a table. Table not deleted")
				self.menu_pre_game()
			else:
				table = input("Table name: ")
				self.player.request_delete_table(table, self.sock)

		elif(option == 5): # request to join a table
			if(self.player_not_in_table()):
				table = input("Table name: ")
				self.player.request_join_table(table, self.sock)
			else:
				client_logger.warning("Player is already in table " + self.player.table + ". Player didn't join table " + table)
				self.menu_pre_game()


		elif(option == 6): # request to leave a table
			if(self.player_not_in_table()):
				client_logger.warning("Player is not in a table. Player didn't leave a table")
				self.menu_pre_game()
			else:
				table = input("Table name: ")
				self.player.request_leave_table(table, self.sock)

	def menu_in_game(self):
		print("Playing")

client = Client()

client.run()