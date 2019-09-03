from ..location import Location
from . import Message, EncryptedMessage, MessageErr
from typing import Optional


class LocationUpdate(Message):
    def __init__(self, loc: Location, cred: EncryptedMessage):
        self.loc = loc
        self.cred = cred

    def __str__(self) -> str:
        return 'LocationUpdate<%s %s>' % (self.loc, self.cred)

    def to_dict(self) -> dict:
        d = {
            'loc': self.loc.to_dict(),
            'cred': self.cred.to_dict(),
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['LocationUpdate']:
        loc = Location.from_dict(d['loc'])
        if not loc:
            return None
        ecred = EncryptedMessage.from_dict(d['cred'])
        if not ecred:
            return None
        return LocationUpdate(loc, ecred)

    def __eq__(self, rhs) -> bool:
        return self.loc == rhs.loc \
            and self.cred == rhs.cred


class LocationUpdateRespErr(MessageErr):
    Malformed = 'Message was not a valid LocationUpdate'


class LocationUpdateResp(Message):
    def __init__(
            self,
            cred: Optional[EncryptedMessage],
            err: Optional[MessageErr]):
        self.ok = err is None
        self.cred = cred
        self.err = err

    def __str__(self) -> str:
        return 'LocationUpdateResp<%s %s %s>' % (self.ok, self.cred, self.err)

    def __eq__(self, rhs) -> bool:
        if not isinstance(rhs, LocationUpdateResp):
            return False
        return self.to_dict() == rhs.to_dict()

    def to_dict(self) -> dict:
        cred = None if self.cred is None else self.cred.to_dict()
        err = None if self.err is None else self.err.value
        d = {
            'err': err,
            'cred': cred,
        }
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> Optional['LocationUpdateResp']:
        if 'err' not in d or 'cred' not in d:
            return None
        cred = None if d['cred'] is None \
            else EncryptedMessage.from_dict(d['cred'])
        err = None if d['err'] is None \
            else LocationUpdateRespErr(d['err'])
        return LocationUpdateResp(cred, err)
