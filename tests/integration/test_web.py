import pytest
from rela.core import server
from rela.lib import db, crypto, user, location as loca
from rela.lib.messages import SignedMessage, Message, EncryptedMessage
from rela.lib.messages import account, location, getinfo
import flask
import time

BAD_JSON_ERR = {'err': 'Must speak json, idiot'}
SK1 = crypto.Seckey((111).to_bytes(32, byteorder='big'))
SK2 = crypto.Seckey((222).to_bytes(32, byteorder='big'))
U1 = user.User('Jim1', SK1.pubkey)  # no rowid. must fetch from db again
U2 = user.User('Sam2', SK2.pubkey)  # no rowid. must fetch from db again


@pytest.fixture
def client():
    success, db_conn = db.connect(':memory:', server.DEF_SCHEMA)
    assert success
    db.insert_user(db_conn, U1)
    db.insert_user(db_conn, U2)
    with server.app.app_context():
        assert 'db' not in flask.g
        flask.g.db = db_conn
        with server.app.test_client() as client:
            yield client
    pass


def get_cred(u: user.User) -> EncryptedMessage:
    cred = account.AccountCred(u, time.time() + server.CRED_LIFETIME)
    scred = SignedMessage.sign(cred, server.IDKEY)
    ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    return ecred


def test_account_create_happy(client):
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    req = SignedMessage.sign(account.AccountReq('Saul3', sk.pubkey), sk)
    rv = client.post(
        '/account/create',
        json=req.to_dict(),
    )
    resp = Message.from_dict(rv.json)
    assert isinstance(resp, account.AuthResp)
    assert resp.err is None
    assert resp.cred is not None
    user_db = db.user_with_pk(flask.g.db, sk.pubkey)
    assert user_db.nick == 'Saul3'
    assert user_db.pk == sk.pubkey
    valid_cred, _ = server.validate_credchal(resp.cred, user_db)
    assert valid_cred


def test_all_not_json(client):
    ROUTES = [
        '/account/create',
        '/location/update',
        '/getinfo/location',
        '/account/challenge/gen',
        '/account/challenge/verify',
    ]
    for route in ROUTES:
        rv = client.post(route, data=b'foo')
        assert rv.status_code == 400
        assert rv.json == BAD_JSON_ERR


def test_location_update_happy(client):
    u = db.user_with_pk(flask.g.db, U1.pk)
    ecred = get_cred(u)
    loc = loca.Location(u, loca.Coords(12, 34), time.time())
    lu = location.LocationUpdate(loc, ecred)
    req = SignedMessage.sign(lu, SK1)
    rv = client.post(
        '/location/update',
        json=req.to_dict(),
    )
    assert rv.status_code == 200
    resp = Message.from_dict(rv.json)
    assert isinstance(resp, location.LocationUpdateResp)
    assert resp.err is None
    valid_cred, _ = server.validate_credchal(resp.cred, u)
    assert valid_cred


def test_getinfo_location(client):
    u_us = db.user_with_pk(flask.g.db, U1.pk)
    u_them = db.user_with_pk(flask.g.db, U2.pk)
    ecred = get_cred(u_us)
    loc = loca.Location(u_them, loca.Coords(12, 34), time.time())
    db.insert_location(flask.g.db, loc)
    gil = getinfo.GetInfoLocation(u_them.pk, ecred, count=1)
    req = SignedMessage.sign(gil, SK1)
    rv = client.post(
        '/getinfo/location',
        json=req.to_dict(),
    )
    assert rv.status_code == 200
    resp = Message.from_dict(rv.json)
    assert isinstance(resp, getinfo.GetInfoRespLocation)
    assert resp.ok
    assert resp.err is None
    assert len(resp.locs) == 1
    assert resp.locs[0] == loc


def test_account_challenge_gen(client):
    u = db.user_with_pk(flask.g.db, U1.pk)
    req = SignedMessage.sign(account.AuthReq(u.pk), SK1)
    rv = client.post(
        '/account/challenge/gen',
        json=req.to_dict(),
    )
    assert rv.status_code == 200
    eresp = Message.from_dict(rv.json)
    assert isinstance(eresp, EncryptedMessage)
    sresp = EncryptedMessage.dec(eresp, server.ENCKEY)
    resp, pk_used = sresp.unwrap()
    assert isinstance(resp, account.AuthChallenge)
    assert pk_used == server.IDKEY.pubkey
    assert resp.user == u


def test_account_challenge_verify(client):
    u = db.user_with_pk(flask.g.db, U1.pk)
    echal = server.generate_auth_challenge(u)
    req = SignedMessage.sign(account.AuthChallengeResp(echal), SK1)
    rv = client.post(
        '/account/challenge/verify',
        json=req.to_dict(),
    )
    assert rv.status_code == 200
    resp = Message.from_dict(rv.json)
    assert isinstance(resp, account.AuthResp)
    assert resp.err is None
    assert isinstance(resp.cred, EncryptedMessage)
    scred = EncryptedMessage.dec(resp.cred, server.ENCKEY)
    assert scred.is_valid()
    cred, pk_used = scred.unwrap()
    assert pk_used == server.IDKEY.pubkey
    assert cred.user == u
    assert cred.expire > time.time()


def test_account_full_auth_handshake(client):
    u = db.user_with_pk(flask.g.db, U1.pk)
    req1 = SignedMessage.sign(account.AuthReq(u.pk), SK1)
    rv1 = client.post(
        '/account/challenge/gen',
        json=req1.to_dict(),
    )
    assert rv1.status_code == 200
    echal = Message.from_dict(rv1.json)
    assert isinstance(echal, EncryptedMessage)
    schal = EncryptedMessage.dec(echal, server.ENCKEY)
    assert schal.is_valid()
    chal, pk_used = schal.unwrap()
    assert isinstance(chal, account.AuthChallenge)
    assert pk_used == server.IDKEY.pubkey
    req2 = SignedMessage.sign(account.AuthChallengeResp(echal), SK1)
    rv2 = client.post(
        '/account/challenge/verify',
        json=req2.to_dict(),
    )
    assert rv2.status_code == 200
    resp = Message.from_dict(rv2.json)
    assert resp.err is None
    assert isinstance(resp.cred, EncryptedMessage)
    scred = EncryptedMessage.dec(resp.cred, server.ENCKEY)
    assert scred.is_valid()
    cred, pk_used = scred.unwrap()
    assert isinstance(cred, account.AccountCred)
    assert pk_used == server.IDKEY.pubkey
