from ugh.lib.messages.location import LocationUpdate
from ugh.lib.location import Coords
from ugh.lib.user import User
from ugh.lib.crypto import Pubkey
import time

U = User('Foo', Pubkey((1).to_bytes(32, byteorder='big')), rowid=420)
C = Coords(4, 20)


def test_locationupdate_init():
    now = time.time()
    lu = LocationUpdate(U, C, now)
    assert lu.user == U
    assert lu.coords == C
    assert lu.at == now


def test_locationupdate_str():
    now = time.time()
    lu = LocationUpdate(U, C, now)
    s = 'LocationUpdate<%s %s %s>' % (U, C, now)
    assert str(lu) == s
