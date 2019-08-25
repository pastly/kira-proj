import sqlite3
import logging
from base64 import b64encode, b64decode
from .crypto import Pubkey

log = logging.getLogger(__name__)

DB_SCHEMA = '''
CREATE TABLE users (nick TEXT NOT NULL, pk Pubkey UNIQUE);
'''


class User:
    def __init__(self, nick: str, pk: Pubkey, rowid=None):
        self.nick = nick
        self.pk = pk
        self.rowid = rowid

    @staticmethod
    def from_row(r: sqlite3.Row):
        return User(r['nick'], r['pk'], rowid=r['rowid'])

    @staticmethod
    def from_dict(d: dict):
        pk = Pubkey(b64decode(d['pk']))
        return User(
            d['nick'], pk, rowid=d['rowid'] if 'rowid' in d else None)

    def to_dict(self) -> dict:
        return {
            'nick': self.nick,
            'pk': b64encode(bytes(self.pk)).decode('utf-8'),
            'rowid': self.rowid,
        }

    def __str__(self):
        return 'User<{id} {n} {pk}>'.format(
            id=self.rowid, n=self.nick, pk=self.pk)

    def __eq__(self, rhs):
        return self.nick == rhs.nick \
            and self.rowid == rhs.rowid \
            and self.pk == rhs.pk
