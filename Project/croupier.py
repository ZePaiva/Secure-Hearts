from hearts import *
import json

class Croupier:
	def __init__(self, deck=[], players=[]):
		self.deck = deck.copy()
		self.players = players.copy()
		self.players_order = []

	def update_deck(self, deck):
		self.deck = deck.copy()

	def update_players(self, players):
		self.players = players.copy()

	def give_cards(self):
		assert(len(self.players) == 4)
		shuffled = shuffle(self.deck.copy())
		hands = [[],[],[],[]]
		for i in range(0, len(shuffled)):
			hands[i%4].append(shuffled[i])

		for i in range(0, len(self.players)):
			connection, address = self.players[i]
			payload = {
				"operation":"croupier@give_cards",
				"address": address[0] + ":" + str(address[1]),
				"hand": hands[i]
			}
			connection.send(json.dumps(payload).encode())

	def give_order(self, first_player):
		self.players_order = [first_player]
		remaining_players = self.players.copy()
		remaining_players.remove(first_player)
		remaining_players = shuffle(remaining_players)
		self.players_order.extend(remaining_players)

		for i in range(0, len(self.players_order)):
			connection, address = self.players_order[i]
			payload = {
				"operation":"croupier@give_order_of_player",
				"address": address[0] + ":" + str(address[1]),
				"order":i
			}
			connection.send(json.dumps(payload).encode())

	def demand_play_card(self, current_idx):
		current_player = self.players_order[current_idx]
		connection, address = current_player
		payload = {
			"operation":"croupier@play_card",
			"address": address[0] + ":" + str(address[1]),
			"order": current_idx,
			"your_turn":True #this is pretty useless but let's go with it
		}
		connection.send(json.dumps(payload).encode())

	def give_cards_to_loser(self, loser_idx, table_cards):
		player = self.players_order[loser_idx]
		connection, address = player
		payload = {
			"operation":"croupier@give_cards_to_loser",
			"address": address[0] + ":" + str(address[1]),
			"loser_order": loser_idx,
			"cards": table_cards,
			"points": get_score(table_cards)
		}
		connection.send(json.dumps(payload).encode())
		self.players_order = self.players_order[loser_idx:] + self.players_order[:loser_idx]

		for i in range(0, len(self.players_order)):
			connection, address = self.players_order[i]
			payload = {
				"operation":"croupier@give_order_of_player",
				"address": address[0] + ":" + str(address[1]),
				"order":i
			}
			connection.send(json.dumps(payload).encode())
		

