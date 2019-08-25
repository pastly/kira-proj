from ugh.lib import db
from ugh.lib import user
from ugh.lib import crypto
from ugh.lib.messages import Stub, SignedMessage, account
from ugh.core import server


SK1 = crypto.Seckey((111).to_bytes(32, byteorder='big'))
SK2 = crypto.Seckey((222).to_bytes(32, byteorder='big'))

server.IDKEY = crypto.Seckey((98734982984).to_bytes(32, byteorder='big'))

def get_db():
    success, db_conn = db.connect(':memory:', server.DEF_SCHEMA)
    assert success
    db.insert_user(db_conn, user.User('Jim1', SK1.pubkey))
    db.insert_user(db_conn, user.User('Sam2', SK2.pubkey))
    return db_conn


def test_account_req_resp_happy():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    req = SignedMessage.sign(account.AccountReq('Saul3', sk.pubkey), sk)
    resp = server.handle_account_request(db_conn, req)
    assert resp.created
    assert resp.err is None
    assert type(resp.cred.msg) == account.AccountCred


def test_account_req_resp_malformed():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    # Supposed to be signing an AccountReq, but instead signing a junk message
    req = SignedMessage.sign(Stub(420), sk)
    resp = server.handle_account_request(db_conn, req)
    assert not resp.created
    assert resp.err == account.AccountRespErr.Malformed


def test_account_req_resp_wrongpubkey():
    db_conn = get_db()
    sk_wrong = crypto.Seckey((420).to_bytes(32, byteorder='big'))
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    u = user.User('Saul3', sk.pubkey)
    # sign the request with the wrong seckey so it can't verify with the
    # correct pubkey
    req = SignedMessage.sign(
        account.AccountReq(u.nick, u.pk), sk_wrong)
    resp = server.handle_account_request(db_conn, req)
    assert not resp.created
    assert resp.err == account.AccountRespErr.WrongPubkey


def test_account_req_resp_badsig():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    u = user.User('Saul3', sk.pubkey)
    req = SignedMessage.sign(account.AccountReq(u.nick, u.pk), sk)
    # change message after it has been signed so that it won't verify
    req.msg_bytes = b'foo'
    resp = server.handle_account_request(db_conn, req)
    assert not resp.created
    assert resp.err is account.AccountRespErr.BadSig


def test_account_req_resp_pubkeyexists():
    db_conn = get_db()
    # create user with a pubkey that is already in use by another user
    u = user.User('Saul3', SK1.pubkey)
    req = SignedMessage.sign(account.AccountReq(u.nick, u.pk), SK1)
    resp = server.handle_account_request(db_conn, req)
    assert not resp.created
    assert resp.err == account.AccountRespErr.PubkeyExists
