from argparse import ArgumentDefaultsHelpFormatter
import logging
from ..lib.messages.account import AccountReq
from ..lib.messages import Message
from ..lib.user import Pubkey
from nacl.signing import SigningKey

log = logging.getLogger(__name__)


def gen_parser(sub):
    d = ''
    _ = sub.add_parser(
        'client', description=d,
        formatter_class=ArgumentDefaultsHelpFormatter)


def main(args, conf):
    log.info('client')
    sk = SigningKey.generate()
    req = AccountReq("Matt", Pubkey(bytes(sk.verify_key)))
    log.info(req.to_dict())
    log.info(req)
    req = Message.from_dict(req.to_dict())
    log.info(req)
    return 0
