from ..user import User
from ..location import Coords
from . import Message


class LocationUpdate(Message):
    def __init__(self, u: User, c: Coords, t: float):
        self.user = u
        self.coords = c
        self.at = t

    def __str__(self) -> str:
        return 'LocationUpdate<%s %s %s>' % (self.user, self.coords, self.at)
