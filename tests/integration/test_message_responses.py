from ugh.lib import db
from ugh.lib import user
from ugh.lib import crypto
from ugh.lib import location as loca
from ugh.lib.messages import Stub, SignedMessage, EncryptedMessage, CredErr,\
    SignedMessageErr
from ugh.lib.messages import account, getinfo, location
from ugh.core import server
import time
import random


SK1 = crypto.Seckey((111).to_bytes(32, byteorder='big'))
SK2 = crypto.Seckey((222).to_bytes(32, byteorder='big'))
U1 = user.User('Jim1', SK1.pubkey)  # no rowid. must fetch from db again
U2 = user.User('Sam2', SK2.pubkey)  # no rowid. must fetch from db again

server.IDKEY = crypto.Seckey((98734982984).to_bytes(32, byteorder='big'))
server.ENCKEY = crypto.Enckey.gen()


def get_db():
    success, db_conn = db.connect(':memory:', server.DEF_SCHEMA)
    assert success
    db.insert_user(db_conn, U1)
    db.insert_user(db_conn, U2)
    return db_conn


def insert_many_locs(db_conn, user):
    def rand_time():
        return 1 + random.random()

    count = 0
    for lat in [0, 20, 40, 60, 80]:
        for long in [0, 45, 90, 135]:
            loc = loca.Location(user, loca.Coords(lat, long), rand_time())
            db.insert_location(db_conn, loc)
            loc = loca.Location(user, loca.Coords(-lat, long), rand_time())
            db.insert_location(db_conn, loc)
            loc = loca.Location(user, loca.Coords(lat, -long), rand_time())
            db.insert_location(db_conn, loc)
            loc = loca.Location(user, loca.Coords(-lat, -long), rand_time())
            db.insert_location(db_conn, loc)
            count += 4
    return count


def get_cred(
        u: user.User,
        scred_stub: bool = False,
        scred_munge: bool = False,
        cred_stub: bool = False,
        cred_wrong_key: bool = False,
        cred_expired: bool = False,
        cred_wrong_user: bool = False,
        ) -> EncryptedMessage:
    if scred_stub:
        ecred = EncryptedMessage.enc(Stub(34444), server.ENCKEY)
    elif scred_munge:
        cred = account.AccountCred(u, time.time() + server.CRED_LIFETIME)
        scred = SignedMessage.sign(cred, server.IDKEY)
        scred.msg_bytes = b'fooooo'
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    elif cred_stub:
        scred = SignedMessage.sign(Stub(2342), server.IDKEY)
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    elif cred_wrong_key:
        sk = crypto.Seckey((9879).to_bytes(32, byteorder='big'))
        cred = account.AccountCred(u, time.time() + server.CRED_LIFETIME)
        scred = SignedMessage.sign(cred, sk)
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    elif cred_expired:
        cred = account.AccountCred(u, time.time() - 0.00001)
        scred = SignedMessage.sign(cred, server.IDKEY)
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    elif cred_wrong_user:
        assert u != U2
        fake_u = user.User(U2.nick, U2.pk, rowid=11)
        cred = account.AccountCred(fake_u, time.time() + server.CRED_LIFETIME)
        scred = SignedMessage.sign(cred, server.IDKEY)
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    else:
        cred = account.AccountCred(u, time.time() + server.CRED_LIFETIME)
        scred = SignedMessage.sign(cred, server.IDKEY)
        ecred = EncryptedMessage.enc(scred, server.ENCKEY)
    return ecred


def expire_from_ecred(
        ecred: EncryptedMessage, ek: crypto.Enckey, pk: crypto.Pubkey) \
        -> float:
    scred = ecred.dec(ek)
    assert isinstance(scred, SignedMessage)
    cred, pk_used = scred.unwrap()
    assert pk_used == pk
    assert isinstance(cred, account.AccountCred)
    return cred.expire


def test_account_req_resp_happy():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    req = SignedMessage.sign(account.AccountReq('Saul3', sk.pubkey), sk)
    resp = server.handle_account_request(db_conn, req)
    assert resp.err is None
    assert isinstance(resp.cred, EncryptedMessage)
    assert isinstance(resp.cred.dec(server.ENCKEY), SignedMessage)
    cred, pk_used = resp.cred.dec(server.ENCKEY).unwrap()
    assert isinstance(cred, account.AccountCred)
    assert pk_used == server.IDKEY.pubkey


def test_account_req_resp_db_inserted():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    req = SignedMessage.sign(account.AccountReq('Saul3', sk.pubkey), sk)
    server.handle_account_request(db_conn, req)
    u_out = db.user_with_pk(db_conn, sk.pubkey)
    assert u_out.rowid
    assert u_out.nick == 'Saul3'
    assert u_out.pk == sk.pubkey


def test_account_req_resp_malformed():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    # Supposed to be signing an AccountReq, but instead signing a junk message
    req = SignedMessage.sign(Stub(420), sk)
    resp = server.handle_account_request(db_conn, req)
    assert resp.cred is None
    assert resp.err == account.AuthRespErr.Malformed


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
    assert resp.cred is None
    assert resp.err == account.AuthRespErr.WrongPubkey


def test_account_req_resp_badsig():
    db_conn = get_db()
    sk = crypto.Seckey((333).to_bytes(32, byteorder='big'))
    u = user.User('Saul3', sk.pubkey)
    req = SignedMessage.sign(account.AccountReq(u.nick, u.pk), sk)
    # change message after it has been signed so that it won't verify
    req.msg_bytes = b'foo'
    resp = server.handle_account_request(db_conn, req)
    assert resp.cred is None
    assert resp.err is account.AuthRespErr.BadSig


def test_account_req_resp_pubkeyexists():
    db_conn = get_db()
    # create user with a pubkey that is already in use by another user
    u = user.User('Saul3', SK1.pubkey)
    req = SignedMessage.sign(account.AccountReq(u.nick, u.pk), SK1)
    resp = server.handle_account_request(db_conn, req)
    assert resp.cred is None
    assert resp.err == account.AuthRespErr.PubkeyExists


def test_location_update_happy():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    original_expire = expire_from_ecred(
        ecred, server.ENCKEY, server.IDKEY.pubkey)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert resp.ok
    assert isinstance(resp.cred, EncryptedMessage)
    scred = EncryptedMessage.dec(resp.cred, server.ENCKEY)
    cred, pk_used = SignedMessage.unwrap(scred)
    assert pk_used == server.IDKEY.pubkey
    assert cred.expire > original_expire
    assert resp.err is None


def test_location_update_db_inserted():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    server.handle_location_update(db_conn, slu)
    db_locs = list(db.locations_for_user(db_conn, u))
    assert len(db_locs) == 1
    assert loc.rowid is None
    loc.rowid = db_locs[0].rowid
    assert db_locs[0] == loc


def test_location_update_badsig():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    # ruin the sig in the signed location update
    slu.msg_bytes = b'foo'
    resp = server.handle_location_update(db_conn, slu)
    assert type(resp) == location.LocationUpdateResp
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == SignedMessageErr.BadSig


def test_location_update_malformed():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    _ = get_cred(u)
    # Sign a Stub instead of a LocationUpate
    slu = SignedMessage.sign(Stub(90210), SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert type(resp) == location.LocationUpdateResp
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == location.LocationUpdateRespErr.Malformed


def test_location_update_badecred_1():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    # use a Stub instead of encrypted signed AccountCred
    lu = location.LocationUpdate(loc, Stub(90210))
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == location.LocationUpdateRespErr.Malformed


def test_location_update_badecred_2():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    # munge the enc part of the encrypted signed account cred
    ecred.ctext_nonce = b'nnnnnnnnnnnnnnnnnnnnnnnneeeeeeee'
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.Malformed


def test_location_update_badecred_3():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    # munge the enc part of the encrypted signed account cred
    ecred.ctext_nonce = b'fooooo'
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.Malformed


def test_location_update_badscred_1():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # ecred is correct but contains a Stub instead of SignedMessage
    ecred = get_cred(u, scred_stub=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.Malformed


def test_location_update_badscred_2():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # ecred is correct but contains a broken SignedMessage
    ecred = get_cred(u, scred_munge=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.Malformed


def test_location_update_badcred_1():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # ecred is correct and contains good SignedMessage, but the SignedMessage
    # contains a Stub
    ecred = get_cred(u, cred_stub=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.Malformed


def test_location_update_badcred_2():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # ecred is correct and contains good SignedMessage, but the SignedMessage
    # is signed by the wrong key
    ecred = get_cred(u, cred_wrong_key=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.BadCred


def test_location_update_expired_cred():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # cred is expired
    ecred = get_cred(u, cred_expired=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.BadCred


def test_location_update_wrong_user():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    # credential is for a user other than the one who signed the message
    ecred = get_cred(u, cred_wrong_user=True)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    slu = SignedMessage.sign(lu, SK1)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == CredErr.WrongUser


def test_location_update_unknown_user():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    loc = location.Location(u, loca.Coords(42, 69), time.time())
    lu = location.LocationUpdate(loc, ecred)
    # user who signed this message is not even in the db
    fake_sk = crypto.Seckey((1).to_bytes(32, byteorder='big'))
    slu = SignedMessage.sign(lu, fake_sk)
    resp = server.handle_location_update(db_conn, slu)
    assert not resp.ok
    assert resp.cred is None  # TODO
    assert resp.err == SignedMessageErr.UnknownUser


def test_getinfo_unknown_user():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    # user who signed this message is not even in the db
    fake_sk = crypto.Seckey((1).to_bytes(32, byteorder='big'))
    gi = SignedMessage.sign(getinfo.GetInfo(u.pk, ecred), fake_sk)
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == SignedMessageErr.UnknownUser


def test_getinfo_badsig():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    gi = SignedMessage.sign(getinfo.GetInfo(u.pk, ecred), SK1)
    # munge the signed message so it doesn't verify
    gi.msg_bytes = b'nnnnnnnnnnnnnnnnnnnnnnnnaaaaaaaaaaaa'
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == SignedMessageErr.BadSig


def test_getinfo_not_getinfo():
    db_conn = get_db()
    # not a GetInfo
    gi = SignedMessage.sign(Stub(1), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == getinfo.GetInfoRespErr.Malformed


def test_getinfo_badcred():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    # munge the cred so it isn't valid
    ecred.ctext_nonce = b'0000000000000000000000000'
    gi = SignedMessage.sign(getinfo.GetInfo(u.pk, ecred), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == CredErr.Malformed


def test_getinfo_unknown_user_in_req():
    db_conn = get_db()
    # ask about a user with a pubkey that doesn't exist
    fake_pk = crypto.Pubkey((98345).to_bytes(32, byteorder='big'))
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    gi = SignedMessage.sign(getinfo.GetInfo(fake_pk, ecred), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == getinfo.GetInfoRespErr.NoSuchUser


def test_getinfo_notimpl():
    db_conn = get_db()
    u = db.user_with_pk(db_conn, U1.pk)
    ecred = get_cred(u)
    gi = SignedMessage.sign(getinfo.GetInfo(U2.pk, ecred), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert isinstance(gir, getinfo.GetInfoResp)
    assert not gir.ok
    assert gir.err == getinfo.GetInfoRespErr.NotImpl


def test_getinfoloc_happy_default():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    insert_many_locs(db_conn, u_other)
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(getinfo.GetInfoLocation(u_other.pk, ecred), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == 1


def test_getinfoloc_multiple_count_correct_1():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    insert_many_locs(db_conn, u_other)
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(
        getinfo.GetInfoLocation(u_other.pk, ecred, count=5), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == 5


def test_getinfoloc_multiple_count_correct_2():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    num_locs = insert_many_locs(db_conn, u_other)
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(
        getinfo.GetInfoLocation(u_other.pk, ecred, count=num_locs), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == num_locs


def test_getinfoloc_multiple_count_correct_3():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    num_locs = insert_many_locs(db_conn, u_other)
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(
        getinfo.GetInfoLocation(u_other.pk, ecred, count=num_locs+10), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == num_locs


def test_getinfoloc_multiple_order_correct_1():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    insert_many_locs(db_conn, u_other)
    # when not asking for a specfic order, we get the newest location first,
    # thus it should have the max time of all locations
    max_time = max([
        loc.time for loc in db.locations_for_user(db_conn, u_other)])
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(
        getinfo.GetInfoLocation(u_other.pk, ecred, count=1), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == 1
    assert gir.locs[0].time == max_time


def test_getinfoloc_multiple_order_correct_2():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    insert_many_locs(db_conn, u_other)
    # when asking for newest=False, we should get the oldest location first,
    # thus it should have the min time of all locations
    min_time = min([
        loc.time for loc in db.locations_for_user(db_conn, u_other)])
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(getinfo.GetInfoLocation(
        u_other.pk, ecred, count=1, newest=False), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == 1
    assert gir.locs[0].time == min_time


def test_getinfoloc_multiple_order_correct_3():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    num_locs = insert_many_locs(db_conn, u_other)
    # when not asking for a specfic order, we get the newest location first,
    # every subsequent location should have a smaller time
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(
        getinfo.GetInfoLocation(u_other.pk, ecred, count=num_locs), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == num_locs
    last_time = 999999999999999
    for loc in gir.locs:
        assert loc.time < last_time
        last_time = loc.time


def test_getinfoloc_multiple_order_correct_4():
    db_conn = get_db()
    u_me = db.user_with_pk(db_conn, U1.pk)
    u_other = db.user_with_pk(db_conn, U2.pk)
    num_locs = insert_many_locs(db_conn, u_other)
    # when asking for newest=False, we should get the oldest location first,
    # every subsequent location should have a smaller time
    ecred = get_cred(u_me)
    gi = SignedMessage.sign(getinfo.GetInfoLocation(
        u_other.pk, ecred, count=num_locs, newest=False), SK1)
    gir = server.handle_getinfo(db_conn, gi)
    assert gir.ok
    assert gir.err is None
    assert len(gir.locs) == num_locs
    last_time = -999999999999
    for loc in gir.locs:
        assert loc.time > last_time
        last_time = loc.time
