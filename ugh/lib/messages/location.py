from ..location import Location
from . import Message, EncryptedMessage


class LocationUpdate(Message):
    def __init__(self, loc: Location, cred: EncryptedMessage):
        self.loc = loc
        self.cred = cred

    def __str__(self) -> str:
        return 'LocationUpdate<%s %s>' % (self.loc, self.cred)
