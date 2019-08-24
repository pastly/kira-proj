from base64 import b64encode, b64decode
from ..user import Pubkey
from . import Message
import logging

log = logging.getLogger(__name__)


class AccountReq(Message):
    def __init__(self, nick: str, pk: Pubkey):
        self.nick = nick
        self.pk = pk

    def __str__(self):
        return 'AccountReq<{n} {pk}>'.format(
            n=self.nick, pk=self.pk,
        )

    def to_dict(self) -> dict:
        d = {
            'nick': self.nick,
            'pk': b64encode(bytes(self.pk)).decode('utf-8'),
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict):
        return AccountReq(
            d['nick'],
            Pubkey(b64decode(d['pk'].encode('utf-8'))),
        )

    def __eq__(self, rhs):
        return self.nick == rhs.nick \
            and self.pk == rhs.pk


class AccountResp(Message):
    def __init__(self):
        pass
