# -*- coding: utf-8 -*-
import sqlite3


class DbConnector:
    def __init__(self, db_file):
        try:
            with open(db_file):
                self.db_file = db_file
        except IOError:
            raise IOError('Did you forget to make a copy of the sample for "%s"?' % db_file)

        self.connection = sqlite3.connect(db_file)
        self.cursor = self.connection.cursor()

    def query(self, sql, *binds):
        return self.cursor.execute(sql, binds)

    def execute(self, sql, *binds):
        self.cursor.execute(sql, binds)
        self.connection.commit()

    def close(self):
        self.connection.close()