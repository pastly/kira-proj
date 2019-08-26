from ugh.lib.location import Coords
import pytest


TEST_COORDS_GOOD = [
    (44, 0), (-44, 0),
    (0, 44), (0, -44),
    (-90, -180), (-90, 180),
    (90, 180), (90, -180),
    (0, 0),
    (0.00001, 0), (0.00001, 0.00001), (0, 0.00001),
]

TEST_COORDS_BAD = [
    (-90.00001, 0), (90.00001, 0),
    (0, 180.000001), (0, -180.000001),
]


def test_coords_init_happy():
    for lat, long in TEST_COORDS_GOOD:
        loc = Coords(lat, long)
        assert loc.lat == lat
        assert loc.long == long


def test_coords_init_bad():
    for lat, long in TEST_COORDS_BAD:
        with pytest.raises(AssertionError):
            Coords(lat, long)


def test_coords_str():
    for lat, long in TEST_COORDS_GOOD:
        loc = Coords(lat, long)
        s = 'Coords<lat=%f long=%f>' % (lat, long)
        assert str(loc) == s


def test_coords_dict_identity():
    for lat, long in TEST_COORDS_GOOD:
        first = Coords(lat, long)
        second = Coords.from_dict(first.to_dict())
        assert first == second


def test_coords_sql_identity():
    for lat, long in TEST_COORDS_GOOD:
        first = Coords(lat, long)
        second = Coords.sql_convert(Coords.sql_adapt(first))
        assert first == second
