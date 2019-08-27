from argparse import ArgumentDefaultsHelpFormatter
from base64 import b64encode, b64decode
import logging
import sqlite3
import nacl
from ..lib import db
from ..lib import user
from ..lib import location
from ..lib import crypto
from ..lib.messages.account import AccountReq, AccountResp, AccountRespErr,\
    AccountCred
from ..lib.messages.location import LocationUpdate, LocationUpdateResp,\
    LocationUpdateRespErr
from ..lib.messages import SignedMessage, EncryptedMessage, SignedMessageErr,\
    CredErr
import time
from typing import Tuple, Union


log = logging.getLogger(__name__)
DEF_SCHEMA = user.DB_SCHEMA + location.DB_SCHEMA

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


def refresh_credential(cred: AccountCred) -> EncryptedMessage:
    cred.expire = time.time() + CRED_LIFETIME
    scred = SignedMessage.sign(cred, IDKEY)
    ecred = EncryptedMessage.enc(scred, ENCKEY)
    return ecred


def validate_credential(ecred: EncryptedMessage, user: user.User) -> \
        Tuple[bool, Union[AccountCred, CredErr]]:
    # Caller must at least make sure the given message is an EncryptedMessage
    assert isinstance(ecred, EncryptedMessage)
    # make sure it was encrypted by us (will be None if it wasn't)
    scred = ecred.try_dec(ENCKEY)
    # make sure it contains a signed message
    if scred is None or not isinstance(scred, SignedMessage):
        return False, CredErr.Malformed
    assert isinstance(scred, SignedMessage)
    # make sure the signature is valid
    if not scred.is_valid():
        return False, CredErr.Malformed
    cred, cred_pk = scred.unwrap()
    # make sure the contained cred is actually an AccountCred
    if not isinstance(cred, AccountCred):
        return False, CredErr.Malformed
    assert isinstance(cred, AccountCred)
    assert isinstance(cred_pk, crypto.Pubkey)
    # make sure it was signed by us
    if not cred_pk == IDKEY.pubkey:
        return False, CredErr.BadCred
    # make sure it hasn't expired
    if time.time() > cred.expire:
        return False, CredErr.BadCred
    # make sure credit is for correct user
    if cred.user != user:
        return False, CredErr.WrongUser
    # all good, yo
    return True, cred


def handle_account_request(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> AccountResp:
    if not smsg.is_valid():
        return AccountResp(False, None, AccountRespErr.BadSig)
    req, pk_used = smsg.unwrap()
    if not isinstance(req, AccountReq):
        return AccountResp(False, None, AccountRespErr.Malformed)
    if req.pk != pk_used:
        return AccountResp(False, None, AccountRespErr.WrongPubkey)
    if db.user_with_pk(db_conn, req.pk):
        return AccountResp(False, None, AccountRespErr.PubkeyExists)
    u = user.User(req.nick, req.pk)
    u = db.insert_user(db_conn, u)
    cred = AccountCred.gen(u, CRED_LIFETIME)
    scred = SignedMessage.sign(cred, IDKEY)
    ecred = EncryptedMessage.enc(scred, ENCKEY)
    return AccountResp(True, ecred, None)


def handle_location_update(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> LocationUpdateResp:
    if not smsg.is_valid():
        return LocationUpdateResp(False, None, SignedMessageErr.BadSig)
    loc_update, pk_used = smsg.unwrap()
    if not isinstance(loc_update, LocationUpdate):
        return LocationUpdateResp(False, None, LocationUpdateRespErr.Malformed)
    user = db.user_with_pk(db_conn, pk_used)
    if not user:
        return LocationUpdateResp(False, None, SignedMessageErr.UnknownUser)
    # OK to assert on this as we should not have been able to contract a
    # LocationUpdate if its cred isn't a valid EncryptedMessage
    assert isinstance(loc_update.cred, EncryptedMessage)
    valid_cred, cred_or_err = validate_credential(loc_update.cred, user)
    if not valid_cred:
        assert isinstance(cred_or_err, CredErr)
        return LocationUpdateResp(False, None, cred_or_err)
    assert isinstance(cred_or_err, AccountCred)
    db.insert_location(db_conn, loc_update.loc)
    return LocationUpdateResp(True, refresh_credential(cred_or_err), None)


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
    pk1 = (973495827942749234).to_bytes(32, byteorder='big')
    pk2 = (98723948672836472898479).to_bytes(32, byteorder='big')
    u1 = db.insert_user(db_conn, user.User('Jim', crypto.Pubkey(pk1)))
    u2 = db.insert_user(db_conn, user.User('Sam', crypto.Pubkey(pk2)))
    for u in db.get_users(db_conn):
        log.debug('%s', u)
    loc1 = location.Location(u1, location.Coords(42, 69), time.time())
    loc2 = location.Location(u2, location.Coords(89.9, 0), time.time())
    loc3 = location.Location(u2, location.Coords(0, -4.1), time.time())
    db.insert_location(db_conn, loc1)
    db.insert_location(db_conn, loc2)
    db.insert_location(db_conn, loc3)
    for loc in db.get_locations(db_conn):
        log.debug('%s', loc)
    return 0
