import sqlite3
from .user import User

DB_SCHEMA = '''
CREATE TABLE Locations (
    coords Coords,
    time REAL, -- Unix timestamps
    user INTEGER,
    FOREIGN KEY(user) REFERENCES users(rowid)
);
'''


class Location:
    def __init__(self, u: User, c: 'Coords', t: float, rowid: int = None):
        self.user = u
        self.coords = c
        self.time = t
        self.rowid = rowid

    @staticmethod
    def from_row(r: sqlite3.Row) -> 'Location':
        u = User(r['nick'], r['pk'], rowid=r['user'])
        return Location(
            u, r['coords'], r['time'],
            rowid=r['rowid'] if 'rowid' in r else None,
        )

    def __str__(self) -> str:
        return 'Location<{r} {u} {c} {t}>'.format(
            r=self.rowid, u=self.user, c=self.coords, t=self.time,
        )

    def __eq__(self, rhs) -> bool:
        return self.user == rhs.user \
            and self.coords == rhs.coords \
            and self.time == rhs.time \
            and self.rowid == rhs.rowid

    def to_dict(self) -> dict:
        return {
            'user': self.user.to_dict(),
            'coords': self.coords.to_dict(),
            'time': self.time,
        }

    @staticmethod
    def from_dict(d: dict) -> 'Location':
        return Location(
            User.from_dict(d['user']),
            Coords.from_dict(d['coords']),
            d['time'],
        )


class Coords:
    def __init__(self, lat: float, long: float):
        assert lat <= 90 and lat >= -90
        assert long <= 180 and long >= -180
        self.lat = lat
        self.long = long

    def __str__(self) -> str:
        return 'Coords<lat=%f long=%f>' % (self.lat, self.long)

    def to_dict(self) -> dict:
        return {
            'lat': self.lat,
            'long': self.long,
        }

    @staticmethod
    def from_dict(d: dict) -> 'Coords':
        return Coords(d['lat'], d['long'])

    def __eq__(self, rhs) -> bool:
        if not isinstance(rhs, Coords):
            return False
        return self.lat == rhs.lat and self.long == rhs.long

    @staticmethod
    def sql_adapt(c: 'Coords') -> bytes:
        s = '%f;%f' % (c.lat, c.long)
        return s.encode('utf-8')

    @staticmethod
    def sql_convert(b: bytes) -> 'Coords':
        s = b.decode('utf-8')
        lat, long = [float(part) for part in s.split(';')]
        return Coords(lat, long)


sqlite3.register_adapter(Coords, Coords.sql_adapt)
sqlite3.register_converter('coords', Coords.sql_convert)
