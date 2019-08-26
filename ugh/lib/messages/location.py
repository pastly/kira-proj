from ..location import Location
from . import Message, EncryptedMessage


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
    def from_dict(d: dict) -> 'LocationUpdate':
        return LocationUpdate(
            Location.from_dict(d['loc']),
            EncryptedMessage.from_dict(d['cred']),
        )

    def __eq__(self, rhs) -> bool:
        return self.loc == rhs.loc \
            and self.cred == rhs.cred
