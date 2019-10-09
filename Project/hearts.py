
"""
Hearts: H  
Diamonds: D
Spades: S
Clubs: C

Queens: QUEEN
Kings: KING
Knight: KNIGHT
Ace: ACE

OBJECTIVE:
To be the player with the lowest 
score at the end of the game. 
When one player hits the agreed-upon score or higher, 
the game ends; and the player with the lowest score wins.

RULES:
At the end of each hand, players count the number of hearts they have
taken as well as the queen of spades, if applicable. 
Hearts count as one point each and the queen counts 13 points.
Each heart - 1 point
The Q - 13 points
The aggregate total of all scores for each hand must be a multiple of 26.
The game is usually played to 100 points (some play to 50).
When a player takes all 13 hearts and the queen of spades in one hand, 
instead of losing 26 points, that player scores zero and each of his 
opponents score an additional 26 points.

DEALING:
Deal the cards one at a time, face down, clockwise. 
In a four-player game, each is dealt 13 cards; 
in a three-player game, the 2 of diamonds should be removed, and each player gets 17 cards; 
in a five-player game, the 2 of diamonds and 2 of clubs should be removed so that each player will get 10 cards.

PLAYING:
The player holding the 2 of clubs after the pass makes the opening lead. 
If the 2 has been removed for the three handed game, then the 3 of clubs is led.
Each player must follow suit if possible. 
If a player is void of the suit led, a card of any other suit may be discarded. 
However, if a player has no clubs when the first trick is led, a heart or the 
queen of spades cannot be discarded. The highest card of the suit led wins a 
trick and the winner of that trick leads next. There is no trump suit.

The winner of the trick collects it and places it face down. Hearts may not be led 
until a heart or the queen of spades has been discarded. 
The queen does not have to be discarded at the first opportunity.

The queen can be led at any time.

"""

import random

cards = [
	"2H","3H","4H","5H","6H","7H","8H","9H","10H","QUEENH","KNIGHTH","KINGH","ACEH",
	"2D","3D","4D","5D","6D","7D","8D","9D","10D","QUEEND","KNIGHTD","KINGD","ACED",
	"2S","3S","4S","5S","6S","7S","8S","9S","10S","QUEENS","KNIGHTS","KINGS","ACES",
	"2C","3C","4C","5C","6C","7C","8C","9C","10C","QUEENC","KNIGHTC","KINGC","ACEC"
]

order = ["2","3","4","5","6","7","8","9","10","KNIGHT","QUEEN","KING", "ACE"]

def value(card):
	# check for hearts
	if card[-1] == "H":
		return 1
	if card == "QUEEN_S":
		return 13
	return 0

def get_score(cards):
	score = 0
	for card in cards:
		score += value(card)
	return score

def shuffle(cards, n=1):
	c = cards
	for i in range(0,n):
		random.shuffle(c)
	return c

def get_higher_card(cards, suit):
	hc = ''
	rank = -1
	for card in cards:
		if card[-1] == suit:
			if order.index(card[:-1]) > rank:
				rank = order.index(card[:-1])
				hc = card
	return hc