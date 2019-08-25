import nacl.signing
import sqlite3


class Pubkey(nacl.signing.VerifyKey):
    @staticmethod
    def sql_adapt(pk) -> bytes:
        # b = pk.pk.to_bytes(32, byteorder='big')
        # assert len(b) == 32
        # return b
        return bytes(pk)

    @staticmethod
    def sql_convert(b: bytes):
        # assert len(b) == 32
        # return Pubkey(int.from_bytes(b, byteorder='big'))
        return Pubkey(b)

    def __str__(self):
        return 'Pubkey<{pk}>'.format(
            pk=int.from_bytes(bytes(self), byteorder='big'))


class Seckey(nacl.signing.SigningKey):
    @property
    def pubkey(self):
        return Pubkey(bytes(self.verify_key))

    def __str__(self):
        return 'Seckey<{k}>'.format(
            k=int.from_bytes(bytes(self), byteorder='big'))


sqlite3.register_adapter(Pubkey, Pubkey.sql_adapt)
sqlite3.register_converter('pubkey', Pubkey.sql_convert)
