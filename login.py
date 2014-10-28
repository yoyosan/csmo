# -*- coding: utf-8 -*-
import httplib
import json
import urllib2
import requests
import base64
import time
import re
import rsa
import random
import logging
import config
import pprint
from model import browser
from lib import exceptions

DEBUG = False

if DEBUG:
    httplib.HTTPConnection.debuglevel = 1
    logging.basicConfig()  # you need to initialize logging, otherwise you will not see anything from requests
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True

sessions = {}


def init_session(role):
    sessions[role] = requests.Session()
    sessions[role].headers = config.INIT_HEADERS


# trader session
init_session('trader')
# tradee session(main account)
init_session('tradee')


def get_trader_session():
    return sessions['trader']


def get_tradee_session():
    return sessions['tradee']


def do_login(account):
    logging.debug('Trying to get RSA key for account %s' % account['username'])

    session = get_trader_session()
    if is_main(account):
        logging.debug('Switching to tradee session!')
        session = get_tradee_session()

    # attempt to get the rsa key
    data = {
        'username': account['username'],
        'donotcache': int(time.time())
    }
    resp_body = post_request(
        config.URLS['getrsakey'],
        session,
        data=data, timeout=config.TIMEOUT
    )

    auth = {}

    if 'publickey_mod' in resp_body \
            and 'publickey_exp' in resp_body \
            and 'timestamp' in resp_body:
        auth['mod'] = resp_body['publickey_mod']
        auth['exp'] = resp_body['publickey_exp']
        auth['timestamp'] = resp_body['timestamp']
    else:
        logging.debug('Failed to get the public key details!')
        exit('Failed to get the public key!')

    # encrypt the password using the modulus and exponent
    pub_key = rsa.PublicKey(int(auth['mod'], 16), int(auth['exp'], 16))
    password = account['password']
    if config.OBFUSCATED_PASSWORDS:
        password = base64.b64decode(password)
    password_rsa = rsa.encrypt(password, pub_key)
    # needs base64 encoding
    password_rsa = base64.b64encode(password_rsa)

    data['captchagid'] = '-1'
    data['rsatimestamp'] = auth['timestamp']
    data['remember_login'] = 'true'
    data['password'] = password_rsa
    resp_login_body = post_request(
        config.URLS['dologin'],
        session,
        data=data, timeout=config.TIMEOUT
    )

    resp_login2 = ''
    if 'emailauth_needed' in resp_login_body \
            and resp_login_body['emailauth_needed']:
        # steam guard protection popped
        data['emailsteamid'] = resp_login_body['emailsteamid']
        email_auth = raw_input('Please provide the code sent through e-mail: ')
        data['emailauth'] = email_auth.upper()
        data['loginfriendlyname'] = 'mypc-%s' % random.randrange(5000, 10000)

        resp_login2 = post_request(
            config.URLS['dologin'],
            session,
            data=data, timeout=config.TIMEOUT
        )

    if 'captcha_needed' in resp_login_body \
            and resp_login_body['captcha_needed']:
        # we're pretty much fucked!
        logging.debug('Captcha detected! Do a manual login!')
        exit('Do a manual login :(')

    browser.save_cookie(
        account['username'],
        requests.utils.dict_from_cookiejar(session.cookies),
        resp_login2
    )


def trade_offer(tradee_account, trader_account):
    logging.debug('=====================================')
    logging.debug('Beginning trade offer...')
    logging.debug('=====================================')
    logging.debug('Getting trader inventory %s...' % trader_account['username'])
    logging.debug('=====================================')

    # get trader inventory, using the steam id
    trader_extra_data = browser.get_extra_data(trader_account['username'])
    trader_inventory = get_request(
        config.URLS['trader_inventory'] % trader_extra_data['transfer_parameters']['steamid'],
        get_trader_session()
    )
    trader_cookies = requests.utils.dict_from_cookiejar(get_trader_session().cookies)
    # browser.save_cookie(
    #     trader_account['username'],
    #     trader_cookies
    # )

    print 'Trader cookies: ', trader_cookies

    # logging.debug('Getting tradee inventory %s...' % tradee_account['username'])
    tradee_extra_data = browser.get_extra_data(tradee_account['username'])
    # tradee_inventory = get_request(
    #     config.URLS['trader_inventory'] % tradee_extra_data['transfer_parameters']['steamid'],
    #     get_trader_session()
    # )
    # browser.save_cookie(
    #     tradee_account['username'],
    #     requests.utils.dict_from_cookiejar(get_tradee_session().cookies)
    # )

    # important cookies for trading, should we keep them?
    musthave_cookies = get_request(
        config.URLS['trade_check'] % tradee_account['partnerid'],
        get_trader_session()
    )
    if musthave_cookies:
        browser.save_cookie(
            trader_account['username'],
            requests.utils.dict_from_cookiejar(musthave_cookies)
        )
        get_trader_session().cookies = browser.get_cookie(trader_account['username'])

    if 'rgInventory' in trader_inventory:
        if len(trader_inventory['rgInventory']) == 0:
            logging.error('\t<======== Empty inventory for "%s"! ========>', trader_account['username'])
            raise Exception('Failed to retrieve inventory!')

        trade_offer = {
            'newversion': True,
            'version': 1,
            'me': {
                'assets': [],
                'currency': [],
                'ready': False
            },
            'them': {
                'assets': [],
                'currency': [],
                'ready': False
            },
        }
        for k, v in trader_inventory['rgInventory'].iteritems():
            description_id = '%s_%s' % (v['classid'], v['instanceid'])
            market_name = trader_inventory['rgDescriptions'][description_id]['market_name']
            for trade_regexp in config.TRADE_ITEMS:
                if re.match(trade_regexp, market_name):
                    trade_offer['me']['assets'].append(dict(appid=730,
                                                            contextid=2,
                                                            amount=1,
                                                            assetid=v['id']))
                    trade_offer['version'] += 1
                    break
        print 'Trade offer: ', trade_offer

        if trade_offer['version'] == 1:
            logging.warn('No items to trade from %s', trader_account['username'])
            return

        data = {
            'sessionid': urllib2.unquote(trader_cookies['sessionid']),
            'partner': tradee_extra_data['transfer_parameters']['steamid'],
            'json_tradeoffer': json.dumps(trade_offer, separators=(',', ':')),
            'trade_offer_create_params': json.dumps({}),
            'tradeoffermessage': 'yolo'
        }

        print 'Data: ', data
        response = post_request(
            config.URLS['trade_offer'],
            get_trader_session(),
            data=data, timeout=config.TIMEOUT
        )

        print response
    # description = tradee_inventory['rgDescriptions']['%s_%s' % (class_id, instance_id)]
    #             if description:
    #                 market_name = description['market_name']
    #                 quality = description['tags'][1]['name']
    #
    #             print '''
    # Class ID: %s, Instance ID: %s, Item ID: %s, Market name: %s, Quality: %s
    #             ''' % (class_id, instance_id, item_id, market_name, quality)

    # if 'main' in account and account['main']:
    #     # TODO replace this shite
    #     friend_id = '162393529'
    #     get_request(config.URLS['trade_check'] % friend_id)
    # trade bravo cases - assetid: 93588811


def post_request(url, session, **kwargs):
    return process_request(url, session, 'post', **kwargs)


def get_request(url, session, **kwargs):
    return process_request(url, session, 'get', **kwargs)


def process_request(url, session, rtype='post', **kwargs):
    result = None
    response = None

    try:
        time.sleep(1)

        print 'Request type: ', rtype
        print 'Request params: ', kwargs

        response = getattr(session, rtype)(url, **kwargs)

        print 'Status Code: ', response.status_code
        print 'Headers:', response.headers
        print 'Response history: ', response.history
        print 'Session cookies: ', requests.utils.dict_from_cookiejar(session.cookies)

        for history in response.history:
            print 'Status code: ', history.status_code
            print 'History cookies: ', requests.utils.dict_from_cookiejar(history.cookies)
            # treat response codes different from 200
            if history.status_code in [requests.codes.moved_permanently, requests.codes.found]:
                # redirection cookies should be set
                cookies = requests.utils.dict_from_cookiejar(history.cookies)
                if 'steamRememberLoginError' in cookies:
                    raise exceptions.SessionError('Need to login!')
            elif history.status_code == requests.codes.server_error:
                # some error, raise an exception!
                print history
                exit()

        result = json.loads(response.text)
    except ValueError as e:
        if response.history:
            if response.history[0]:
                return session.cookies
            # TODO

        print e.message
        with open('trade.html', 'w') as f:
            f.write(response.text)

    print 'URL: ', url
    print '======== Result: ', pprint.pprint(result)

    return result


def check_account(account, session):
    account_cookie = browser.get_cookie(account['username'])
    session.cookies = requests.utils.cookiejar_from_dict(account_cookie)
    if not account_cookie \
            or (not 'steamLogin' in account_cookie
                or not 'steamRememberLogin' in account_cookie):
        do_login(account)

    try:
        get_request(
            config.URLS['trade_check'] % account['partnerid'],
            session
        )
    except exceptions.SessionError:
        do_login(account)
        check_account(account, session)


def setup_logging():
    formatter = logging.Formatter(
        fmt='%(asctime)s %(message)s', datefmt='[%d.%m.%Y %H:%M:%S]'
    )
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(formatter)

    fh = logging.FileHandler('csmo.log')
    fh.setLevel(logging.INFO)
    fh.setFormatter(formatter)

    logging.getLogger().setLevel(logging.DEBUG)
    logging.getLogger().addHandler(fh)
    logging.getLogger().addHandler(ch)


def is_main(account):
    return account.get('main', False)


if __name__ == '__main__':
    try:
        setup_logging()
        logging.info('Starting script')
        tradee_account = None

        # handle tradee account(the main account)
        for tradee_account in config.ACCOUNTS:
            if is_main(tradee_account):
                break
        check_account(tradee_account, get_tradee_session())

        # handle traders account
        for trader_account in config.ACCOUNTS:
            if is_main(trader_account):
                continue

            check_account(trader_account, get_trader_session())

            trade_offer(tradee_account, trader_account)

            # if 'main' in account and account['main']:
            # trade_offer(account)
            # time.sleep(2)

    except Exception as ex:
        logging.exception('+++ Exception occurred: %s +++' % ex.message)
    finally:
        logging.warning('Go outside and play, Now!')