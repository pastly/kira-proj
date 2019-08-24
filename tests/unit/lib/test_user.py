from ugh.lib.user import User, Pubkey

PK_VALS = {
    0, 3, 255, 256, 2897,
    1356938545749799165119972480570561420155507632800475359837393562592731987968}  # noqa:E501

NICK_VALS = {
    '', 'Matt',
}


def test_pubkey_init():
    for v in PK_VALS:
        pk = Pubkey(v)
        assert pk.pk == v


def test_pubkey_adapt():
    for v in PK_VALS:
        pk = Pubkey(v)
        b = Pubkey.sql_adapt(pk)
        assert len(b) == 32
        assert int.from_bytes(b, byteorder='big') == v


def test_pubkey_convert():
    for v in PK_VALS:
        b = v.to_bytes(32, byteorder='big')
        pk = Pubkey.sql_convert(b)
        assert pk == Pubkey(v)


def test_pubkey_str():
    for v in PK_VALS:
        s = 'Pubkey<%d>' % (v,)
        assert str(Pubkey(v)) == s


def test_user_init():
    for n in NICK_VALS:
        for pk in [Pubkey(pk) for pk in PK_VALS]:
            u = User(n, pk)
            assert u.nick == n
            assert u.pk == pk
            assert u.rowid is None


def test_user_str():
    for n in NICK_VALS:
        for pk in [Pubkey(pk) for pk in PK_VALS]:
            s = 'User<%s %s %s>' % (None, n, pk)
            u = User(n, pk)
            assert str(u) == s


def test_user_from_dict():
    for n in NICK_VALS:
        for pk in [Pubkey(pk) for pk in PK_VALS]:
            u_expect = User(n, pk)
            u_actual = User.from_dict({'nick': n, 'pk': pk})
            assert u_expect == u_actual
