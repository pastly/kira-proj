from rela.lib.messages.location import LocationUpdate, LocationUpdateResp,\
    LocationUpdateRespErr
from rela.lib.messages.account import AccountCred
from rela.lib.messages import EncryptedMessage, Stub
from rela.lib.location import Location, Coords
from rela.lib.user import User
from rela.lib.crypto import Pubkey, Enckey
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


def test_locationupdate_dict_identity():
    cred = fake_cred()
    first = LocationUpdate(LOC, cred)
    second = LocationUpdate.from_dict(first.to_dict())
    assert first == second


def test_locationupdate_from_dict_invalid_1():
    cred = fake_cred()
    lu = LocationUpdate(Stub(1), cred)
    assert isinstance(lu, LocationUpdate)
    lu = LocationUpdate.from_dict(lu.to_dict())
    assert lu is None


def test_locationupdate_from_dict_invalid_2():
    cred = fake_cred()
    lu = LocationUpdate(Location(Stub(1), C, time.time()), cred)
    assert isinstance(lu, LocationUpdate)
    lu = LocationUpdate.from_dict(lu.to_dict())
    assert lu is None


def test_locationupdate_from_dict_invalid_3():
    cred = fake_cred()
    lu = LocationUpdate(Location(U, Stub(1), time.time()), cred)
    assert isinstance(lu, LocationUpdate)
    lu = LocationUpdate.from_dict(lu.to_dict())
    assert lu is None


def test_locationupdate_from_dict_invalid_4():
    cred = fake_cred()
    lu = LocationUpdate(LOC, cred)
    assert isinstance(lu, LocationUpdate)
    lu_dict = lu.to_dict()
    del lu_dict['loc']['time']
    lu = LocationUpdate.from_dict(lu_dict)
    assert lu is None


def test_locationupdateresp_dict_identity():
    for cred in [None, fake_cred()]:
        for err in [None, LocationUpdateRespErr.Malformed]:
            first = LocationUpdateResp(cred, err)
            second = LocationUpdateResp.from_dict(first.to_dict())
            assert first == second


def test_locationupdateresp_equal_stub():
    lur = LocationUpdateResp(fake_cred(), None)
    assert lur != Stub(1)


def test_locationupdateresp_from_dict_invalid_1():
    d = LocationUpdateResp(fake_cred(), None).to_dict()
    del d['err']
    assert LocationUpdateResp.from_dict(d) is None


def test_locationupdateresp_from_dict_invalid_2():
    d = LocationUpdateResp(fake_cred(), None).to_dict()
    del d['cred']
    assert LocationUpdateResp.from_dict(d) is None
