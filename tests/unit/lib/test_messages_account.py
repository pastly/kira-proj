from ugh.lib.messages.account import AccountReq
from ugh.lib.messages import Message
from ugh.lib.user import Pubkey
from base64 import b64encode, b64decode

PK = Pubkey((1).to_bytes(32, byteorder='big'))
U = 'Foo'


def test_accountreq_dict_identity():
    first = AccountReq(U, PK)
    second = Message.from_dict(first.to_dict())
    assert first == second


def test_accountreq_to_dict():
    ar = AccountReq(U, PK)
    d = ar.to_dict()
    assert d['nick'] == U
    assert Pubkey(b64decode(d['pk'])) == PK


def test_accountreq_from_dict():
    d = {
        'nick': U,
        'pk': b64encode(bytes(PK)).decode('utf-8'),
    }
    ar = AccountReq.from_dict(d)
    assert ar.nick == d['nick']
    assert ar.pk == Pubkey(b64decode(d['pk']))


def test_accountreq_str():
    s = 'AccountReq<%s %s>' % (U, PK)
    ar = AccountReq(U, PK)
    assert str(ar) == s
