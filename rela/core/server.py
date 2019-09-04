from argparse import ArgumentDefaultsHelpFormatter
from base64 import b64encode, b64decode
import logging
import itertools
import sqlite3
import nacl
import flask
from ..lib import db
from ..lib import user
from ..lib import location as loca
from ..lib import crypto
from ..lib.messages import account, location, getinfo
from ..lib.messages import SignedMessage, EncryptedMessage, SignedMessageErr,\
    CredChalErr, Message
import time
from typing import Tuple, Union


log = logging.getLogger(__name__)
app = flask.Flask(__name__)
DEF_SCHEMA = user.DB_SCHEMA + loca.DB_SCHEMA

AUTH_CHAL_LIFETIME: float = 15  # 15 seconds
CRED_LIFETIME: float = 60 * 5  # 5 minutes, in seconds
IDKEY: crypto.Seckey
ENCKEY: crypto.Enckey


def gen_parser(sub):
    d = ''
    p = sub.add_parser(
        'server', description=d,
        formatter_class=ArgumentDefaultsHelpFormatter)
    p.add_argument(
        '--gen-key', action='store_true', help='Utility function. '
        'Generate an identity key, print it, and quit.')


def generate_credential(user: user.User) -> EncryptedMessage:
    cred = account.AccountCred.gen(user, CRED_LIFETIME)
    scred = SignedMessage.sign(cred, IDKEY)
    ecred = EncryptedMessage.enc(scred, ENCKEY)
    return ecred


def refresh_credential(cred: account.AccountCred) -> EncryptedMessage:
    cred.expire = time.time() + CRED_LIFETIME
    scred = SignedMessage.sign(cred, IDKEY)
    ecred = EncryptedMessage.enc(scred, ENCKEY)
    return ecred


def generate_auth_challenge(u: user.User) -> EncryptedMessage:
    assert u.rowid is not None
    expire = time.time() + AUTH_CHAL_LIFETIME
    chal = account.AuthChallenge(u, expire)
    schal = SignedMessage.sign(chal, IDKEY)
    echal = EncryptedMessage.enc(schal, ENCKEY)
    return echal


def validate_credchal(ecred: EncryptedMessage, user: user.User) -> \
        Tuple[bool,
              Union[account.AccountCred, account.AuthChallenge, CredChalErr]]:
    # Caller must at least make sure the given message is an EncryptedMessage
    assert isinstance(ecred, EncryptedMessage)
    # make sure it was encrypted by us (will be None if it wasn't)
    scred = ecred.try_dec(ENCKEY)
    # make sure it contains a signed message
    if scred is None or not isinstance(scred, SignedMessage):
        return False, CredChalErr.Malformed
    assert isinstance(scred, SignedMessage)
    # make sure the signature is valid
    if not scred.is_valid():
        return False, CredChalErr.Malformed
    cred, cred_pk = scred.unwrap()
    # make sure the contained cred is actually an AccountCred or AuthChallenge
    if not isinstance(cred, account.AccountCred) \
            and not isinstance(cred, account.AuthChallenge):
        return False, CredChalErr.Malformed
    assert isinstance(cred, account.AccountCred) \
        or isinstance(cred, account.AuthChallenge)
    assert isinstance(cred_pk, crypto.Pubkey)
    # make sure it was signed by us
    if not cred_pk == IDKEY.pubkey:
        return False, CredChalErr.BadCred
    # make sure it hasn't expired
    if time.time() > cred.expire:
        return False, CredChalErr.BadCred
    # make sure credit is for correct user
    if cred.user != user:
        return False, CredChalErr.WrongUser
    # all good, yo
    return True, cred


def handle_account_request(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> account.AuthResp:
    if not smsg.is_valid():
        return account.AuthResp(None, account.AuthRespErr.BadSig)
    req, pk_used = smsg.unwrap()
    if not isinstance(req, account.AccountReq):
        return account.AuthResp(
            None, account.AuthRespErr.Malformed)
    if req.pk != pk_used:
        return account.AuthResp(
            None, account.AuthRespErr.WrongPubkey)
    if db.user_with_pk(db_conn, req.pk):
        return account.AuthResp(
            None, account.AuthRespErr.PubkeyExists)
    u = user.User(req.nick, req.pk)
    u = db.insert_user(db_conn, u)
    return account.AuthResp(generate_credential(u), None)


def handle_location_update(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> location.LocationUpdateResp:
    if not smsg.is_valid():
        return location.LocationUpdateResp(None, SignedMessageErr.BadSig)
    loc_update, pk_used = smsg.unwrap()
    if not isinstance(loc_update, location.LocationUpdate):
        return location.LocationUpdateResp(
            None, location.LocationUpdateRespErr.Malformed)
    user = db.user_with_pk(db_conn, pk_used)
    if not user:
        return location.LocationUpdateResp(None, SignedMessageErr.UnknownUser)
    # OK to assert on this as we should not have been able to contract a
    # LocationUpdate if its cred isn't a valid EncryptedMessage
    assert isinstance(loc_update.cred, EncryptedMessage)
    valid_cred, cred_or_err = validate_credchal(loc_update.cred, user)
    if not valid_cred:
        assert isinstance(cred_or_err, CredChalErr)
        return location.LocationUpdateResp(None, cred_or_err)
    assert isinstance(cred_or_err, account.AccountCred)
    db.insert_location(db_conn, loc_update.loc)
    return location.LocationUpdateResp(refresh_credential(cred_or_err), None)


def handle_getinfo(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> getinfo.GetInfoResp:
    if not smsg.is_valid():
        return getinfo.GetInfoResp(SignedMessageErr.BadSig)
    gi_req, pk_used = smsg.unwrap()
    if not isinstance(gi_req, getinfo.GetInfo):
        return getinfo.GetInfoResp(getinfo.GetInfoRespErr.Malformed)
    user = db.user_with_pk(db_conn, pk_used)
    if not user:
        return getinfo.GetInfoResp(SignedMessageErr.UnknownUser)
    # OK to assert on this as we should not have been able to contract a
    # GetInfo if its cred isn't a valid EncryptedMessage
    assert isinstance(gi_req.cred, EncryptedMessage)
    valid_cred, cred_or_err = validate_credchal(gi_req.cred, user)
    if not valid_cred:
        assert isinstance(cred_or_err, CredChalErr)
        return getinfo.GetInfoResp(cred_or_err)
    assert isinstance(cred_or_err, account.AccountCred)
    user_in_req = db.user_with_pk(db_conn, gi_req.user_pk)
    if user_in_req is None:
        return getinfo.GetInfoResp(getinfo.GetInfoRespErr.NoSuchUser)
    if type(gi_req) == getinfo.GetInfo:
        return getinfo.GetInfoResp(getinfo.GetInfoRespErr.NotImpl)
    return {  # type: ignore
              # TODO remove when more than one type of GetInfo
        getinfo.GetInfoLocation:
            lambda gi: handle_getinfo_location(db_conn, gi),
    }[type(gi_req)](gi_req)


def handle_getinfo_location(
        db_conn: sqlite3.Connection,
        req: getinfo.GetInfoLocation) -> \
        getinfo.GetInfoResp:
    u = db.user_with_pk(db_conn, req.user_pk)
    # TODO we should actually expect a signed message containing
    # GetInfoLocation and then verify the cred within is valid now and for the
    # user who signed the message
    # TODO should probably return error to user instead of assert here???
    assert isinstance(u, user.User)
    locs = list(itertools.islice(
        db.locations_for_user(db_conn, u, reverse=req.newest),
        0, req.count))
    return getinfo.GetInfoRespLocation(locs, None)


def handle_authreq(
        db_conn: sqlite3.Connection,
        smsg: SignedMessage) -> \
        Union[account.AuthResp, EncryptedMessage]:
    # verify the signed message and extract its contents
    if not smsg.is_valid():
        return account.AuthResp(None, SignedMessageErr.BadSig)
    req, pk_used = smsg.unwrap()
    # if not an AuthReq, return early
    if not isinstance(req, account.AuthReq):
        return account.AuthResp(None, account.AuthRespErr.Malformed)
    # make sure we know the user who made the SignedMessage
    u = db.user_with_pk(db_conn, pk_used)
    if u is None:
        return account.AuthResp(None, SignedMessageErr.UnknownUser)
    assert u is not None
    assert isinstance(u, user.User)
    # make sure they are asking to auth as the same user as who signed the
    # message (probably not actually necessary for the user to sign something
    # containing their own pubkey, but that's how it works ...)
    if pk_used != req.user_pk:
        return account.AuthResp(None, account.AuthRespErr.WrongPubkey)
    # this should be a given as the pk_used came form the signed message and we
    # just verified that the pk in the request is the same as pk_used
    assert u.pk == pk_used
    assert u.pk == req.user_pk
    # generate and return an auth challenge for them
    return generate_auth_challenge(u)


def handle_authchallengeresp(
        db_conn: sqlite3.Connection,
        smsg: SignedMessage) -> \
        Union[account.AuthResp, EncryptedMessage]:
    # verify the signed message and extract its contents
    if not smsg.is_valid():
        return account.AuthResp(None, SignedMessageErr.BadSig)
    req, pk_used = smsg.unwrap()
    # if not an AuthChallengeResp, return early
    if not isinstance(req, account.AuthChallengeResp):
        return account.AuthResp(None, account.AuthRespErr.Malformed)
    # make sure we know the user who made the SignedMessage
    u = db.user_with_pk(db_conn, pk_used)
    if u is None:
        return account.AuthResp(None, SignedMessageErr.UnknownUser)
    assert u is not None
    assert isinstance(u, user.User)
    # OK to assert on this bc we should not have been able to create
    # AuthChallengeResp if it didn't contain an EncryptedMessage
    assert isinstance(req.enc_chal, EncryptedMessage)
    valid_chal, chal_or_err = validate_credchal(req.enc_chal, u)
    if not valid_chal:
        assert isinstance(chal_or_err, CredChalErr)
        return account.AuthResp(None, chal_or_err)
    assert isinstance(chal_or_err, account.AuthChallenge)
    return account.AuthResp(generate_credential(u), None)


def main_gen_key():
    idsk = crypto.Seckey(bytes(nacl.signing.SigningKey.generate()))
    idsk_str = b64encode(bytes(idsk)).decode('utf-8')
    idpk_str = b64encode(bytes(idsk.pubkey)).decode('utf-8')
    enc = crypto.Enckey.gen()
    enc_str = b64encode(enc).decode('utf-8')
    print('Generated secret identity key is', idsk_str)
    print('Generated public identity key is', idpk_str)
    print('Generated encryption key is', enc_str)
    print('Add the following to your config:')
    print('[server]\nidentity = %s\nencryption = %s' % (idsk_str, enc_str))


def update_globals(conf, sk: crypto.Seckey, ek: crypto.Enckey):
    global IDKEY
    IDKEY = sk
    global ENCKEY
    ENCKEY = ek
    if 'cred_lifetime' in conf['server']:
        global CRED_LIFETIME
        lifetime = conf.getfloat('server', 'cred_lifetime')
        log.info('Updating cred_lifetime to %f', lifetime)
        CRED_LIFETIME = lifetime


def bad_request(err_msg: str) -> Tuple[dict, int]:
    return {'err': err_msg}, 400


def bad_req_not_json() -> Tuple[dict, int]:
    return bad_request('Must speak json, idiot')


@app.route('/account/create', methods=['POST'])
def r_account_create():
    if flask.request.content_type != 'application/json':
        return bad_req_not_json()
    req = Message.from_dict(flask.request.json)
    resp = handle_account_request(flask.g.db, req)
    return resp.to_dict()


@app.route('/account/challenge/gen', methods=['POST'])
def r_account_challenge_gen():
    if flask.request.content_type != 'application/json':
        return bad_req_not_json()
    req = Message.from_dict(flask.request.json)
    resp = handle_authreq(flask.g.db, req)
    return resp.to_dict()


@app.route('/account/challenge/verify', methods=['POST'])
def r_account_challenge_verify():
    if flask.request.content_type != 'application/json':
        return bad_req_not_json()
    req = Message.from_dict(flask.request.json)
    resp = handle_authchallengeresp(flask.g.db, req)
    return resp.to_dict()


@app.route('/location/update', methods=['POST'])
def r_location_update():
    if flask.request.content_type != 'application/json':
        return bad_req_not_json()
    req = Message.from_dict(flask.request.json)
    resp = handle_location_update(flask.g.db, req)
    return resp.to_dict()


@app.route('/getinfo/location', methods=['POST'])
def r_getinfo_location():
    if flask.request.content_type != 'application/json':
        return bad_req_not_json()
    req = Message.from_dict(flask.request.json)
    resp = handle_getinfo(flask.g.db, req)
    return resp.to_dict()


def main(args, conf):
    if args.gen_key:
        return main_gen_key()
    sk = crypto.Seckey(b64decode(conf['server']['identity']))
    ek = crypto.Enckey(b64decode(conf['server']['encryption']))
    update_globals(conf, sk, ek)
    pk_str = b64encode(bytes(sk.pubkey)).decode('utf-8')
    log.info('My public key is %s', pk_str)
    success, db_conn = db.connect(
        conf['server']['db_fname'], schema=DEF_SCHEMA)
    if not success:
        return 1
    assert db_conn
    with app.app_context():
        assert 'db' not in flask.g
        flask.g.db = db_conn
        app.config['ENV'] = 'development'
        app.run(
            host=conf['server']['listen_host'],
            port=conf['server']['listen_port'],
            debug=True
        )
