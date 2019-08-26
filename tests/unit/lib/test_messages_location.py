from ugh.lib.messages.location import LocationUpdate
from ugh.lib.messages.account import AccountCred
from ugh.lib.messages import EncryptedMessage
from ugh.lib.location import Location, Coords
from ugh.lib.user import User
from ugh.lib.crypto import Pubkey, Enckey
import time

U = User('Foo', Pubkey((1).to_bytes(32, byteorder='big')), rowid=420)
C = Coords(4, 20)
LOC = Location(U, C, time.time())


def fake_cred():
    cred = AccountCred(U, time.time())
    return EncryptedMessage.enc(cred, Enckey.gen())


def test_locationupdate_init():
    cred = fake_cred()
    lu = LocationUpdate(LOC, cred)
    assert lu.loc == LOC
    assert lu.cred == cred


def test_locationupdate_str():
    cred = fake_cred()
    lu = LocationUpdate(LOC, cred)
    s = 'LocationUpdate<%s %s>' % (LOC, cred)
    assert str(lu) == s
