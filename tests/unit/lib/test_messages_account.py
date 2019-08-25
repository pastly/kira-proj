from ugh.lib.messages import account
from ugh.lib.messages import Message
from ugh.lib.user import Pubkey
from base64 import b64encode, b64decode

PK = Pubkey((1).to_bytes(32, byteorder='big'))
U = 'Foo'


def test_accountreq_dict_identity():
    first = account.AccountReq(U, PK)
    second = Message.from_dict(first.to_dict())
    assert first == second


def test_accountreq_to_dict():
    ar = account.AccountReq(U, PK)
    d = ar.to_dict()
    assert d['nick'] == U
    assert Pubkey(b64decode(d['pk'])) == PK


def test_accountreq_from_dict():
    d = {
        'nick': U,
        'pk': b64encode(bytes(PK)).decode('utf-8'),
    }
    ar = account.AccountReq.from_dict(d)
    assert ar.nick == d['nick']
    assert ar.pk == Pubkey(b64decode(d['pk']))


def test_accountreq_str():
    s = 'AccountReq<%s %s>' % (U, PK)
    ar = account.AccountReq(U, PK)
    assert str(ar) == s


ALL_ACCRESP_ARG_SETS = [
    (True, None),
    (False, account.AccountRespErr.BadSig),
    (False, account.AccountRespErr.BadSig),
    (False, account.AccountRespErr.PubkeyExists),
    (False, account.AccountRespErr.Malformed),
    (False, account.AccountRespErr.WrongPubkey),
]


def test_accountresp_dict_identity():
    for args in ALL_ACCRESP_ARG_SETS:
        first = account.AccountResp(*args)
        second = Message.from_dict(first.to_dict())
        assert first == second


def test_accountresp_to_dict():
    for created, err in ALL_ACCRESP_ARG_SETS:
        ar = account.AccountResp(created, err)
        d = ar.to_dict()
        assert d['created'] == created
        assert d['err'] == err


def test_accountresp_from_dict():
    for created, err in ALL_ACCRESP_ARG_SETS:
        d = {'created': created, 'err': err}
        ar = account.AccountResp.from_dict(d)
        assert ar.created == created
        assert ar.err == err


def test_accountresp_str():
    fmt = 'AccountResp<created={c} err={e} cred={cred}>'
    for created, err in ALL_ACCRESP_ARG_SETS:
        s = fmt.format(c=created, e=err, cred='ayy lmao')
        ar = account.AccountResp(created, err)
        assert str(ar) == s
