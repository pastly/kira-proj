from base64 import b64encode, b64decode
from ..user import User
from ..crypto import Pubkey
from . import Message, EncryptedMessage
import logging
from typing import Optional
from enum import Enum
import time

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
    def from_dict(d: dict) -> 'AccountReq':
        return AccountReq(
            d['nick'],
            Pubkey(b64decode(d['pk'].encode('utf-8'))),
        )

    def __eq__(self, rhs):
        return self.nick == rhs.nick \
            and self.pk == rhs.pk


class AuthRespErr(Enum):
    BadSig = 'The signature is invalid'
    PubkeyExists = 'A user with that pubkey already exists'
    Malformed = 'Message was not a valid AccountReq'
    WrongPubkey = 'Message signed with Seckey other than one associated with '\
        'given Pubkey'


class AuthResp(Message):
    def __init__(
            self,
            cred: Optional[EncryptedMessage],
            err: Optional[AuthRespErr]):
        if err is None:
            assert cred is not None
        else:
            assert cred is None
        self.cred = cred
        self.err = err

    @staticmethod
    def from_dict(d: dict) -> Optional['AuthResp']:
        if 'cred' not in d or 'err' not in d:
            return None
        # both can't be None
        if d['cred'] is None and d['err'] is None:
            return None
        # both can't be non-None either though
        if d['cred'] is not None and d['err'] is not None:
            return None
        # if cred exists, try to make its object
        cred = None if d['cred'] is None \
            else EncryptedMessage.from_dict(d['cred'])
        # if cred exists but couldn't make object, fail
        if cred is None and d['cred'] is not None:
            return None
        # make err if exists
        err = None if d['err'] is None else AuthRespErr(d['err'])
        return AuthResp(cred, err)

    def to_dict(self) -> dict:
        cred = self.cred.to_dict() if self.cred is not None else None
        err = None if self.err is None else self.err.value
        d = {
            'err': err,
            'cred': cred,
        }
        d.update(super().to_dict())
        return d

    def __eq__(self, rhs) -> bool:
        return self.err == rhs.err \
            and self.cred == rhs.cred

    def __str__(self) -> str:
        return 'AuthResp<err={e} cred={cred}>'.format(
            e=self.err, cred=self.cred,
        )


class AccountCred(Message):
    def __init__(self, user: User, expire: float):
        assert user.rowid is not None
        self.user = user
        self.expire = expire  # timestamp it expires

    @staticmethod
    def gen(
            user: User,
            lifetime: float,  # duration, starting at *now*
            now: Optional[float] = None) -> 'AccountCred':
        if now is None:
            now = time.time()
        return AccountCred(user, now + lifetime)

    @staticmethod
    def from_dict(d: dict) -> 'AccountCred':
        u = User.from_dict(d['user'])
        return AccountCred(u, d['expire'])

    def to_dict(self) -> dict:
        d = {
            'user': self.user.to_dict(),
            'expire': self.expire,
        }
        d.update(super().to_dict())
        return d

    def __str__(self) -> str:
        return 'AccountCred<{u} {e}>'.format(
            u=self.user, e=self.expire,
        )

    def __eq__(self, rhs) -> bool:
        return self.user == rhs.user \
            and self.expire == rhs.expire


class AuthReq(Message):
    def __init__(self, user_pk: Pubkey):
        self.user_pk = user_pk

    def to_dict(self) -> dict:
        d = {
            'user_pk': b64encode(bytes(self.user_pk)).decode('utf-8'),
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['AuthReq']:
        if 'user_pk' not in d:
            return None
        return AuthReq(Pubkey(b64decode(d['user_pk'])))

    def __str__(self) -> str:
        return 'AuthReq<%s>' % (self.user_pk,)


class AuthChallenge(Message):
    def __init__(self, user: User, expire: float):
        assert user.rowid is not None
        self.user = user
        self.expire = expire

    def to_dict(self) -> dict:
        d = {
            'user': self.user.to_dict(),
            'expire': self.expire,
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['AuthChallenge']:
        if 'user' not in d or 'expire' not in d:
            return None
        u = User.from_dict(d['user'])
        if u is None:
            return None
        return AuthChallenge(u, d['expire'])

    def __str__(self) -> str:
        return 'AuthChallenge<%s %f>' % (
            self.user, self.expire)


class AuthChallengeResp(Message):
    def __init__(self, enc_chal: EncryptedMessage):
        self.enc_chal = enc_chal

    def to_dict(self) -> dict:
        d = {
            'enc_chal': self.enc_chal.to_dict(),
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['AuthChallengeResp']:
        if 'enc_chal' not in d:
            return None
        enc_chal = EncryptedMessage.from_dict(d['enc_chal'])
        if enc_chal is None:
            return None
        return AuthChallengeResp(enc_chal)

    def __str__(self) -> str:
        return 'AuthChallengeResp<%s>' % (self.enc_chal,)
