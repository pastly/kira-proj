from ugh.lib.location import Location
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


def test_location_init_happy():
    for lat, long in TEST_COORDS_GOOD:
        loc = Location(lat, long)
        assert loc.lat == lat
        assert loc.long == long


def test_location_init_bad():
    for lat, long in TEST_COORDS_BAD:
        with pytest.raises(AssertionError):
            Location(lat, long)


def test_location_str():
    for lat, long in TEST_COORDS_GOOD:
        loc = Location(lat, long)
        s = 'Location<lat=%d long=%d>' % (lat, long)
        assert str(loc) == s
