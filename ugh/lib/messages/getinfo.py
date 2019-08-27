from . import Message, EncryptedMessage
from .. import crypto
from base64 import b64encode, b64decode
from typing import Optional, Union


class GetInfo(Message):
    def __init__(self, user_pk: crypto.Pubkey, cred: EncryptedMessage):
        self.user_pk = user_pk
        self.cred = cred

    def to_dict(self) -> dict:
        d = {
            'user_pk': b64encode(bytes(self.user_pk)).decode('utf-8'),
            'cred': self.cred.to_dict(),
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['GetInfo']:
        if 'user_pk' not in d or 'cred' not in d:
            return None
        user_pk = crypto.Pubkey(b64decode(d['user_pk']))
        ecred = EncryptedMessage.from_dict(d['cred'])
        if not ecred:
            return None
        return GetInfo(user_pk, ecred)

    def __str__(self) -> str:
        return 'GetInfo<%s %s>' % (self.user_pk, self.cred)

    def __eq__(self, rhs) -> bool:
        if not isinstance(rhs, GetInfo):
            return False
        return self.user_pk == rhs.user_pk \
            and self.cred == rhs.cred


class GetInfoLocation(GetInfo):
    def __init__(
            self,
            *gi_args: Union[crypto.Pubkey, EncryptedMessage],
            count: int = 1,
            newest: bool = True):
        assert len(gi_args) == 2
        assert isinstance(gi_args[0], crypto.Pubkey)
        assert isinstance(gi_args[1], EncryptedMessage)
        super().__init__(gi_args[0], gi_args[1])
        self.count = count
        self.newest = newest

    def to_dict(self) -> dict:
        d = {
            'count': self.count,
            'newest': self.newest,
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['GetInfoLocation']:
        if 'count' not in d or 'newest' not in d:
            return None
        gi = GetInfo.from_dict(d)
        if gi is None:
            return None
        count = d['count']
        newest = d['newest']
        del d['count']
        del d['newest']
        return GetInfoLocation(gi.user_pk, gi.cred, count=count, newest=newest)
