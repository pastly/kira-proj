import sqlite3
import logging

log = logging.getLogger(__name__)

DB_SCHEMA = '''
CREATE TABLE users (nick TEXT, pk Pubkey);
'''


class Pubkey:
    def __init__(self, pk: int):
        self.pk = pk

    @staticmethod
    def sql_adapt(pk) -> bytes:
        b = pk.pk.to_bytes(32, byteorder='big')
        assert len(b) == 32
        return b

    @staticmethod
    def sql_convert(b: bytes):
        assert len(b) == 32
        return Pubkey(int.from_bytes(b, byteorder='big'))

    def __str__(self):
        return 'Pubkey<{pk}>'.format(pk=self.pk)

    def __eq__(self, rhs):
        return self.pk == rhs.pk


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
        return User(
            d['nick'], d['pk'], rowid=d['rowid'] if 'rowid' in d else None)

    def __str__(self):
        return 'User<{id} {n} {pk}>'.format(
            id=self.rowid, n=self.nick, pk=self.pk)

    def __eq__(self, rhs):
        return self.nick == rhs.nick \
            and self.rowid == rhs.rowid \
            and self.pk == rhs.pk


sqlite3.register_adapter(Pubkey, Pubkey.sql_adapt)
sqlite3.register_converter('pubkey', Pubkey.sql_convert)
