# -*- coding: utf-8 -*-

OBFUSCATED_PASSWORDS = True

# - if OBFUSCATED_PASSWORDS is True, encode the password with base64 for print obfuscation!
# - set 'main': True for the main account
# - get partnerid from http://steamcommunity.com/actions/PlayerList/?type=friends
#   It's easier to get this from Steam\config\config.vdf
#   Also should change partnerid to something that makes more sense (profileid ?)
ACCOUNTS = {
    {'username': 'user', 'password': 'pass', 'partnerid': 0}
}
URLS = {
    'getrsakey': 'https://steamcommunity.com/login/getrsakey/',
    'dologin': 'https://steamcommunity.com/login/dologin/',
    'trader_inventory': 'http://steamcommunity.com/profiles/%s/inventory/json/730/2/?trading=1',
    'trade_check': 'http://steamcommunity.com/tradeoffer/new/?partner=%s',
    'tradee_inventory': 'http://steamcommunity.com/tradeoffer/new/partnerinventory/',
    'trade_offer': 'https://steamcommunity.com/tradeoffer/new/send',
    'trade_accept_offer': ' https://steamcommunity.com/tradeoffer/%s/accept'
}
# requests timeout, in seconds
TIMEOUT = 5
# initial headers
INIT_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:28.0) Gecko/20100101 Firefox/28.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://steamcommunity.com/tradeoffer/new/?partner=30874969',
    'Host': 'steamcommunity.com',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
}

# class ids of items that will be traded
TRADE_ITEMS = [
    'Operation Breakout Weapon Case',
    'eSports 2014 Summer Case',
    'Huntsman Weapon Case',
    # skins
    '.* \((Battle-Scarred|Well-Worn|Field-Tested|Minimal-Wear|Factory New|)\)$'
]

# DB file
DB_NAME = 'data/csmo.sqlite'