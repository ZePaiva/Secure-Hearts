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

player_log_colors=coloredlogs.parse_encoded_styles('asctime=green;hostname=magenta;levelname=white,bold;name=blue,bold;programname=cyan')
level_colors=coloredlogs.parse_encoded_styles('spam=white;info=blue;debug=green;warning=yellow;error=red;critical=red,bold')
player_logger=logging.getLogger('PLAYER')


class Player:
	def __init__(self, username, log_level='DEBUG'):
		# logging
		coloredlogs.install(level=log_level, fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level_styles=level_colors, field_styles=player_log_colors)

		# game related
		self.username = username
		self.table = -1
		self.points = -1
		self.hand = []
		self.owner = False
		self.in_table = False
		self.playing = False
		self.table = None

	def update_table(self, table):
		self.table = table 
		player_logger.info("Table updated")

	def update_points(self, points):
		self.points = points 
		player_logger.info("Points updated")

	def update_hand(self, hand):
		self.hand = hand.copy()
		player_logger.info("Hand updated")

	def request_join_table(self, table, conn):
		payload = {
			"operation":"player@request_join_table",
			"username": self.username,
			"table": table
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested to join table " + str(table))

	def request_leave_table(self, table, conn):
		payload = {
			"operation":"player@request_leave_table",
			"username":self.username,
			"table":table
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested to leave table " + str(table))

	def request_create_table(self, table, conn):
		payload = {
			"operation":"player@request_create_table",
			"username":self.username,
			"table":table,
			"limit":4
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested to create table " + str(table))


	def request_delete_table(self, table, conn):
		payload = {
			"operation":"player@request_delete_table",
			"username":self.username,
			"table":table
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested to delete table " + str(table))


	def request_tables_online(self, conn):
		payload = {
			"operation":"player@request_tables_online",
			"username":self.username
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested online tables")

	def request_online_users(self, conn):
		payload = {
			"operation":"player@request_online_users",
			"username":self.username
		}

		payload = json.dumps(payload)
		conn.send(payload.encode())
		player_logger.info("Requested usernames of online players")

