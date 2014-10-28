# -*- coding: utf-8 -*-
from contextlib import closing
import json
import time

from lib import DbConnector
import config

# init DB connection
db = DbConnector.DbConnector(config.DB_NAME)


def get_one(criteria, column, table):
    """

    :param criteria:
        {'condition': 'name LIKE ?', 'param': 'bla'}
    :param column: 'content'
    :param table: 'cookie'
    :return:
    """
    exists = db.query('''
    SELECT
        %s
    FROM %s
    WHERE %s
    ''' % (column, table, criteria['condition']), criteria['param']).fetchone()

    if exists:
        return json.loads(exists[0])
    else:
        return None


# with closing(DbConnector.DbConnector(config.DB_NAME)) as db:
def get_cookie(steam_id):
    """

    :param steam_id:
    :return:
    """
    return get_one({'condition': 'steam_id LIKE ?', 'param': steam_id}, 'content', 'cookie')


def get_extra_data(steam_id):
    """

    :param steam_id:
    :return:
    """
    return get_one({'condition': 'steam_id LIKE ?', 'param': steam_id}, 'extra_data', 'cookie')


def save_cookie(steam_id, data, extra_data=None):
    """

    :param steam_id:
    :param data:
    :raise Exception:
    """
    if data is None or len(data) == 0:
        raise Exception('Empty data!')

    def needs_update(old_data, new_data):
        # check whether an update is really needed!
        result = False
        for k, v in new_data.iteritems():
            if k in old_data:
                if v != old_data[k]:
                    result = True
                    break
            else:
                result = True
                break

        return result

    exists = get_cookie(steam_id)
    if exists is None:
        db.execute('''
        INSERT INTO cookie
            VALUES(?, ?, ?, ?)
        ''', steam_id, json.dumps(data), int(time.time()), json.dumps(extra_data))
    else:
        needs_update = needs_update(exists, data)

        if needs_update:
            db.execute('''
            UPDATE cookie SET content = ?, timestamp = ?
                WHERE steam_id LIKE ?''', json.dumps(data), int(time.time()), steam_id)
