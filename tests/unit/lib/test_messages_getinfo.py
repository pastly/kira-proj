from ugh.lib import user
from ugh.lib import crypto
from ugh.lib.messages.getinfo import GetInfo, GetInfoLocation
from ugh.lib.messages import EncryptedMessage, Stub

SK = crypto.Seckey((28379873947).to_bytes(32, byteorder='big'))
U = user.User('Foo', SK.pubkey, rowid=420)


def really_fake_cred() -> EncryptedMessage:
    return EncryptedMessage.enc(Stub(1), crypto.Enckey.gen())


def test_getinfo_dict_identity():
    first = GetInfo(U.pk, really_fake_cred())
    second = GetInfo.from_dict(first.to_dict())
    assert first == second


def test_getinfo_eq_int():
    assert GetInfo(U.pk, really_fake_cred()) != 1


def test_getinfo_dict_no_user():
    gi = GetInfo(U.pk, really_fake_cred())
    d = gi.to_dict()
    del d['user_pk']
    assert GetInfo.from_dict(d) is None


def test_getinfo_dict_no_ecred():
    gi = GetInfo(U.pk, really_fake_cred())
    d = gi.to_dict()
    del d['cred']
    assert GetInfo.from_dict(d) is None


def test_getinfo_dict_bad_ecred():
    gi = GetInfo(U.pk, really_fake_cred())
    d = gi.to_dict()
    d['cred'] = Stub(1).to_dict()
    assert GetInfo.from_dict(d) is None


def test_getinfo_str():
    cred = really_fake_cred()
    s = 'GetInfo<%s %s>' % (U.pk, cred)
    gi = GetInfo(U.pk, cred)
    assert str(gi) == s


def test_getinfoloc_dict_identity():
    first = GetInfoLocation(U.pk, really_fake_cred(), count=44, newest=False)
    second = GetInfoLocation.from_dict(first.to_dict())
    assert first == second


def test_getinfoloc_dict_no_count():
    giloc = GetInfoLocation(U.pk, really_fake_cred(), count=44, newest=False)
    d = giloc.to_dict()
    del d['count']
    assert GetInfoLocation.from_dict(d) is None


def test_getinfoloc_dict_no_newest():
    giloc = GetInfoLocation(U.pk, really_fake_cred(), count=44, newest=False)
    d = giloc.to_dict()
    del d['newest']
    assert GetInfoLocation.from_dict(d) is None


def test_getinfoloc_dict_bad_getinfo():
    giloc = GetInfoLocation(U.pk, really_fake_cred(), count=44, newest=False)
    d = giloc.to_dict()
    del d['user_pk']
    assert GetInfoLocation.from_dict(d) is None
