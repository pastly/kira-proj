class Location:
    def __init__(self, lat: float, long: float):
        assert lat <= 90 and lat >= -90
        assert long <= 180 and long >= -180
        self.lat = lat
        self.long = long

    def __str__(self) -> str:
        return 'Location<lat=%d long=%d>' % (self.lat, self.long)
