from argparse import ArgumentDefaultsHelpFormatter
import logging
from ..lib import db
from ..lib import user

log = logging.getLogger(__name__)
DEF_SCHEMA = user.DB_SCHEMA


def gen_parser(sub):
    d = ''
    _ = sub.add_parser(
        'server', description=d,
        formatter_class=ArgumentDefaultsHelpFormatter)


def main(args, conf):
    log.info('server')
    success, db_conn = db.connect(
        conf['server']['db_fname'], schema=DEF_SCHEMA)
    if not success:
        return 1
    assert db_conn
    db.insert_user(db_conn, user.User('Jim', user.Pubkey(4398198798573948732)))
    db.insert_user(db_conn, user.User('Sam', user.Pubkey(8213948723986128967)))
    for u in db.get_users(db_conn):
        log.debug('%s', u)
    return 0
