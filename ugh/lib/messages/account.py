from base64 import b64encode, b64decode
from ..user import Pubkey
from . import Message
import logging
from typing import Optional
from enum import Enum

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


class AccountRespErr(Enum):
    BadSig = 'The signature is invalid'
    PubkeyExists = 'A user with that pubkey already exists'
    Malformed = 'Message was not a valid AccountReq'
    WrongPubkey = 'Message signed with Seckey other than one associated with '\
        'given Pubkey'


class AccountResp(Message):
    def __init__(self, created: bool, err: Optional[AccountRespErr]):
        if created:
            assert err is None
        if not created:
            assert err is not None
        self.created = created
        self.err = err
        self.cred = 'ayy lmao'

    @staticmethod
    def from_dict(d: dict):
        return AccountResp(
            d['created'],
            d['err'],
            # d['cred'],
        )

    def to_dict(self) -> dict:
        d = {
            'created': self.created,
            'err': self.err,
            'cred': self.cred,
        }
        d.update(super().to_dict())
        return d

    def __eq__(self, rhs) -> bool:
        return self.created == rhs.created \
            and self.err == rhs.err \
            and self.cred == rhs.cred

    def __str__(self) -> str:
        return 'AccountResp<created={c} err={e} cred={cred}>'.format(
            c=self.created, e=self.err, cred=self.cred,
        )
