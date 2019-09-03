from rela.lib.user import User
from rela.lib.crypto import Pubkey
from base64 import b64encode

PK_VALS = {
    0, 3, 255, 256, 2897,
    1356938545749799165119972480570561420155507632800475359837393562592731987968}  # noqa:E501

NICK_VALS = {
    '', 'Matt',
}


def test_user_init():
    for n in NICK_VALS:
        for pk in [Pubkey(v.to_bytes(32, byteorder='big')) for v in PK_VALS]:
            u = User(n, pk)
            assert u.nick == n
            assert u.pk == pk
            assert u.rowid is None


def test_user_str():
    for n in NICK_VALS:
        for pk in [Pubkey(v.to_bytes(32, byteorder='big')) for v in PK_VALS]:
            s = 'User<%s %s %s>' % (None, n, pk)
            u = User(n, pk)
            assert str(u) == s


def test_user_from_dict():
    for n in NICK_VALS:
        for pk in [Pubkey(v.to_bytes(32, byteorder='big')) for v in PK_VALS]:
            u_expect = User(n, pk)
            pk_b64_bytes = b64encode(bytes(pk)).decode('utf-8')
            u_actual = User.from_dict({'nick': n, 'pk': pk_b64_bytes})
            assert u_expect == u_actual


def test_user_dict_identity():
    for n in NICK_VALS:
        for pk in [Pubkey(v.to_bytes(32, byteorder='big')) for v in PK_VALS]:
            for rowid in {None, 44}:
                first = User(n, pk, rowid=rowid)
                second = User.from_dict(first.to_dict())
                assert first == second


def test_user_dict_no_nick():
    d = User('', Pubkey((0).to_bytes(32, byteorder='big'))).to_dict()
    del d['nick']
    assert User.from_dict(d) is None


def test_user_dict_no_pk():
    d = User('', Pubkey((0).to_bytes(32, byteorder='big'))).to_dict()
    del d['pk']
    assert User.from_dict(d) is None
