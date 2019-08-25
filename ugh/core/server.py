from argparse import ArgumentDefaultsHelpFormatter
from typing import Optional
from base64 import b64encode, b64decode
import logging
import sqlite3
import nacl
from ..lib import db
from ..lib import user
from ..lib.messages.account import AccountReq, AccountResp, AccountRespErr,\
    AccountCred
from ..lib.messages import SignedMessage

log = logging.getLogger(__name__)
DEF_SCHEMA = user.DB_SCHEMA

CRED_LIFETIME: float = 60 * 30  # 30 minutes, in seconds
SECKEY: user.Seckey

def gen_parser(sub):
    d = ''
    p = sub.add_parser(
        'server', description=d,
        formatter_class=ArgumentDefaultsHelpFormatter)
    p.add_argument(
        '--gen-key', action='store_true', help='Utility function. '
        'Generate an identity key, print it, and quit.')


def handle_account_request(
        db_conn: sqlite3.Connection, smsg: SignedMessage) \
        -> AccountResp:
    verify, req, pk_used = smsg.verified_unwrap()
    if not verify:
        return AccountResp(False, None, AccountRespErr.BadSig)
    if not isinstance(req, AccountReq):
        return AccountResp(False, None, AccountRespErr.Malformed)
    if req.pk != pk_used:
        return AccountResp(False, None, AccountRespErr.WrongPubkey)
    if db.user_with_pk(db_conn, req.pk):
        return AccountResp(False, None, AccountRespErr.PubkeyExists)
    u = user.User(req.nick, req.pk)
    u = db.insert_user(db_conn, u)
    cred = AccountCred.gen(u, CRED_LIFETIME)
    scred = SignedMessage.sign(cred, SECKEY)
    return AccountResp(True, scred, None)


def main_gen_key():
    sk = user.Seckey(bytes(nacl.signing.SigningKey.generate()))
    sk_str = b64encode(bytes(sk)).decode('utf-8')
    pk_str = b64encode(bytes(sk.pubkey)).decode('utf-8')
    print('Generated secret key is', sk_str)
    print('Generated public key is', pk_str)
    print('Add the following to your config:')
    print('[server]\nidentity = %s' % (sk_str,))


def update_globals(conf, sk: user.Seckey):
    global SECKEY
    SECKEY = sk
    if 'cred_lifetime' in conf['server']:
        global CRED_LIFETIME
        lifetime = conf.getfloat('server', 'cred_lifetime')
        log.info('Updating cred_lifetime to %f', lifetime)
        CRED_LIFETIME = lifetime


def main(args, conf):
    if args.gen_key:
        return main_gen_key()
    sk = user.Seckey(b64decode(conf['server']['identity']))
    update_globals(conf, sk)
    pk_str = b64encode(bytes(sk.pubkey)).decode('utf-8')
    log.info('My public key is %s', pk_str)
    success, db_conn = db.connect(
        conf['server']['db_fname'], schema=DEF_SCHEMA)
    if not success:
        return 1
    assert db_conn
    pk1 = (973495827942749234).to_bytes(32, byteorder='big')
    pk2 = (98723948672836472898479).to_bytes(32, byteorder='big')
    db.insert_user(db_conn, user.User('Jim', user.Pubkey(pk1)))
    db.insert_user(db_conn, user.User('Sam', user.Pubkey(pk2)))
    for u in db.get_users(db_conn):
        log.debug('%s', u)
    return 0
