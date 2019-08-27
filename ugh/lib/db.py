import os
import logging
import sqlite3
from typing import Iterator, Optional
from .user import User, Pubkey
from .location import Location

log = logging.getLogger(__name__)


def insert_user(conn: sqlite3.Connection, u: User) -> User:
    assert u.rowid is None
    q = 'INSERT INTO Users VALUES (?, ?)'
    c = conn.execute(q, (u.nick, u.pk))
    conn.commit()
    u_out = user_with_id(conn, c.lastrowid)
    assert u_out is not None
    return u_out


def insert_location(conn: sqlite3.Connection, loc: Location) -> Location:
    q = 'INSERT INTO Locations VALUES (?, ?, ?)'
    assert loc.user.rowid is not None
    c = conn.execute(q, (loc.coords, loc.time, loc.user.rowid))
    conn.commit()
    loc_out = location_with_id(conn, c.lastrowid)
    assert loc_out is not None
    return loc_out


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
    q = 'SELECT rowid, * from Users'
    c = conn.cursor()
    c.execute(q)
    while True:
        ret = c.fetchone()
        if not ret:
            return
        yield User.from_row(ret)


def get_locations(conn: sqlite3.Connection) -> Iterator[Location]:
    q = 'SELECT Locations.rowid, * from Locations '\
        'INNER JOIN Users ON Users.rowid = Locations.user'
    c = conn.cursor()
    c.execute(q)
    while True:
        ret = c.fetchone()
        if not ret:
            return
        yield Location.from_row(ret)


def user_with_pk(conn: sqlite3.Connection, pk: Pubkey) -> Optional[User]:
    q = 'SELECT rowid, * from Users WHERE pk=?'
    c = conn.execute(q, (pk,))
    ret = c.fetchall()
    assert len(ret) == 0 or len(ret) == 1
    if not len(ret):
        return None
    return User.from_row(ret[0])


def user_with_id(conn: sqlite3.Connection, id: int) -> Optional[User]:
    q = 'SELECT rowid, * from Users WHERE rowid=?'
    c = conn.execute(q, (id,))
    ret = c.fetchall()
    assert len(ret) == 0 or len(ret) == 1
    if not len(ret):
        return None
    return User.from_row(ret[0])


def location_with_id(conn: sqlite3.Connection, id: int) -> Optional[Location]:
    q = 'SELECT Locations.rowid, * from Locations '\
        'INNER JOIN Users ON Users.rowid = Locations.user '\
        'WHERE Locations.rowid=?'
    c = conn.execute(q, (id,))
    ret = c.fetchall()
    assert len(ret) == 0 or len(ret) == 1
    if not len(ret):
        return None
    return Location.from_row(ret[0])


def locations_for_user(
        conn: sqlite3.Connection, u: User, reverse: bool = False) \
        -> Iterator[Location]:
    q = 'SELECT Locations.rowid, * from Locations '\
        'INNER JOIN Users ON Users.rowid = Locations.user '\
        'WHERE Locations.user=? '\
        'ORDER BY Locations.rowid {ord}'.format(
            ord='DESC' if reverse else 'ASC',
        )
    assert u.rowid is not None
    c = conn.execute(q, (u.rowid,))
    while True:
        ret = c.fetchone()
        if not ret:
            return
        yield Location.from_row(ret)
