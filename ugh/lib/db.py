import os
import logging
import sqlite3
from typing import Iterator
from .user import User

log = logging.getLogger(__name__)


def insert_user(conn: sqlite3.Connection, u: User):
    q = 'INSERT INTO users VALUES (?, ?)'
    conn.execute(q, (u.nick, u.pk))
    conn.commit()


def connect(fname: str, schema=None):
    if fname == ':memory:' or not os.path.exists(fname):
        if not schema:
            log.error(
                '%s does not exist and no default schema provided', fname)
            return False, None
        log.info('Creating db at %s', fname)
        conn = sqlite3.connect(fname, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.executescript(schema)
        conn.commit()
        return True, conn
    log.info('Opening db at %s', fname)
    conn = sqlite3.connect(fname, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return True, conn


def get_users(conn: sqlite3.Connection) -> Iterator[User]:
    q = 'SELECT rowid, * from users'
    c = conn.cursor()
    c.execute(q)
    while True:
        ret = c.fetchone()
        if not ret:
            return
        yield User.from_row(ret)
