import json
import struct
from utils.server_utils import send

class Player:
    def __init__(self, hand=[], player_id=''):
        self.hand = hand
        self.id = player_id
        self.order = None
        self.points = 0
        self.used_cards = []

    def update_hand(self, hand):
        self.hand = hand

    def update_id(self, player_id):
        self.id = player_id

    def update_order(self, order):
        self.order = order

    def update_points(self, points):
        self.points += points

    def update_used_cards(self, cards):
        self.used_cards.extend(cards)


    def communicate_has_2C(self, s):
        payload = {
            "operation":"player@has_two_of_clubs",
            "player_id": self.id,
            "has_2C": "2C" in self.hand     
        }
        # s.send(json.dumps(payload).encode())
        send(s, payload)


    def communicate_is_ready(self, s):
        payload = {
            "operation":"player@is_ready",
            "player_id": self.id,
            "order": self.order,
            "ready": True
        }
        # s.send(json.dumps(payload).encode())
        send(s, payload)


    def play(self, s):
        card = ''
        print('Your hand: ' + str(self.hand))
        while card not in self.hand:
            card = input('Play a card from your hand: ')
        self.hand.remove(card)
        payload = {
            "operation":"player@play",
            "player_id": self.id,
            "order": self.order,
            "card" : str(card)  
        }
        # s.send(json.dumps(payload).encode())
        send(s, payload)


