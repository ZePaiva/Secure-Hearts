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

# hearts
from hearts import *


croupier_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
croupier_logger=logging.getLogger('CROUPIER')

class Croupier:
	def __init__(self, log_level='DEBUG'):
		# logging
		coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=croupier_log_colors)

		self.tables = {}
		self.players = {}
		self.players_conn = {}
		self.tables_limit = 4
		self.tables_number = 0

		# hearts
		self.hearts = Hearts()



	def add_player(self, conn, addr, username):
		if(conn not in self.players.keys()):
			self.players[conn] = {
				"conn":conn,
				"address":addr,
				"username":username,
				"table":None,
				"points":-1
			}

			self.players_conn[username] = conn 
			croupier_logger.info("Player " + str(username) + " registered")
			return 1
		
		croupier_logger.warning("Player already exists")
		return 0

	def get_username(self, conn):
		for username in self.players_conn.keys():
			if(conn == self.players_conn[username]):
				break
		return username

	def delete_player(self, conn):
		if(conn in self.players.keys()):
			try:
				# delete table if player is owner
				for table in self.tables.keys():
					if(self.players_conn[self.tables[table]["owner"]] == conn):
						croupier_logger.info("Player " + self.tables[table]["owner"] + " left and is the owner of table " + table)
						request = {
							"table":table,
							"username":self.tables[table]["owner"],
						}
						self.delete_table(request, conn)
					
					else:
						# remove player from table otherwise
						for username in self.tables[table]["players"].keys():
							if(self.players_conn[username] == conn):
								croupier_logger.info("Player " + username + " left and is in a table")
								request = {
									"table":table,
									"username":username
								}
								self.remove_player_table(request, conn)
			except:
				# exception: size of self.tables.keys() changed during iteration (because table was deleted)
				# just ignore this exception in order to continue with the normal flow
				pass

			# delete player
			del self.players[conn]

			# delete player connection
			for username in self.players_conn.keys():
				if(conn == self.players_conn[username]):
					del self.players_conn[username]
					break

			croupier_logger.info("Player " + str(username) + " deleted")
			return 1
		
		croupier_logger.warning("Player " + str(username) + " not deleted")
		return 0

	def send_online_players(self, conn):
		payload = {
			"operation":"croupier@send_online_players",
			"players":{}
		}

		for connection in self.players.keys():
			payload["players"][self.players[connection]["username"]]={
				"username":self.players[connection]["username"],
				"table":self.players[connection]["table"],
				"points":self.players[connection]["points"],
				"status":"online"
			}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		croupier_logger.info("Sent list of online users back to " + self.players[conn]["username"])



	def create_table(self, request, conn):
		if((request["table"] not in self.tables.keys()) and self.tables_number < 4):
			# update tables
			self.tables[request["table"]] = {
				"owner":request["username"],
				"limit": request["limit"],
				"table":request["table"],
				"nplayers":1,
				"ready":False,
				"cards":self.hearts.cards.copy(),
				"players":{
					request["username"]:{
						"username":request["username"],
						"points":0,
						"hand":[]
					}
				}
			}

			# update players
			self.players[conn]["table"] = request["table"]
			self.players[conn]["points"] = 0

			croupier_logger.info("Table " + str(request["table"]) + " was successfully created")
			return 1
	
		croupier_logger.warning("Table " + str(request["table"]) + " was not created")
		return 0
		

	def delete_table(self, request, conn):
		if((request["table"] in self.tables.keys()) and (self.tables[request["table"]]["owner"] == request["username"])):
			if(conn == self.players_conn[request["username"]]):
				# update players
				self.players[conn]["table"] = None
				self.players[conn]["points"] = -1

				for username in self.tables[request["table"]]["players"].keys():
					connection = self.players_conn[username]
					self.players[connection]["table"] = None
					self.players[connection]["points"] = -1

					payload = {
						"operation":"croupier@table_deleted",
						"message": "The table you were in was deleted. You're not in a table anymore"
					}

					payload = json.dumps(payload)
					connection.send(payload.encode())
					croupier_logger.info("Informed " + username + " about the deletion of the table")

				# update tables
				del self.tables[request["table"]]
				croupier_logger.info("Table " + str(request["table"]) + " deleted with success")
				return 1
			else:
				croupier_logger.warning("Table " + str(request["table"]) + " not deleted - permission denied")
				return 0
		croupier_logger.warning("Table " + str(request["table"]) + " not deleted - didn't exist")
		return 0


	def join_player_table(self, request, conn):
		username = request["username"]
		table = request["table"]

		if(table in self.tables.keys() and self.tables[table]["nplayers"] < self.tables[table]["limit"]):
			if(username not in self.tables[table]["players"].keys()):
				# update table
				self.tables[table]["players"][username] = {
					"username":username,
					"points":0,
					"hand":[]
				}
				self.tables[table]["nplayers"] += 1

				# update player
				self.players[conn]["table"] = table
				self.players[conn]["points"] = 0

				croupier_logger.info("Player " + username + " added to table " + table + " with success")

				# check readiness of table
				if(self.tables[table]["nplayers"] == self.tables[table]["limit"]):
					self.tables[table]["ready"] = True
					connections = []
					# get conn of players in the table
					for username in self.tables[table]["players"].keys():
						connections.append(self.players_conn[username])

					croupier_logger.info("Table " + table + " is ready")
					return connections

				return 1
		
			croupier_logger.warning("Player " + username + " already in table " + table)
			return 0

		croupier_logger.warning("Table " + table + " isn't created or is already full")
		return 0

	def remove_player_table(self, request, conn):
		username = request["username"]
		table = request["table"]

		if(table in self.tables.keys()):
			owner_conn = self.players_conn[self.tables[table]["owner"]]
			if(username in self.tables[table]["players"].keys()):
				if(conn == owner_conn): # if the owner wants to leave the table
					croupier_logger.info("The owner of the table " + table + " left")
					self.delete_table(request, conn)
				else:
					# update table
					del self.tables[table]["players"][username]
					self.tables[table]["nplayers"] -= 1

					# update player
					self.players[conn]["table"] = None
					self.players[conn]["points"] = -1

					croupier_logger.info("Player " + username + " left the table " + table)
				return 1
		
			croupier_logger.warning("Player " + username + " was already not in the table " + table)
			return 0			

		croupier_logger.warning("Table " + table + " does not exist. Player was not removed")
		return 0

	def send_online_tables(self, conn):
		tables = self.tables.copy()
		tables["operation"] = "croupier@send_online_tables"
		payload = json.dumps(tables)
		conn.send(payload.encode())
		croupier_logger.info("Sent list of online tables")
