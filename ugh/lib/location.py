class Coords:
    def __init__(self, lat: float, long: float):
        assert lat <= 90 and lat >= -90
        assert long <= 180 and long >= -180
        self.lat = lat
        self.long = long

    def __str__(self) -> str:
        return 'Coords<lat=%d long=%d>' % (self.lat, self.long)

    def to_dict(self) -> dict:
        return {
            'lat': self.lat,
            'long': self.long,
        }

    @staticmethod
    def from_dict(d: dict) -> 'Coords':
        return Coords(d['lat'], d['long'])

    def __eq__(self, rhs) -> bool:
        return self.lat == rhs.lat and self.long == rhs.long
