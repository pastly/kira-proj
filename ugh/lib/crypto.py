import nacl.signing
import nacl.secret
import nacl.utils
import sqlite3
from base64 import b64encode


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
        return 'Pubkey<%s..%s (%d bytes)>' % (
            b64encode(bytes(self)[:6]).decode('utf-8'),
            b64encode(bytes(self)[-6:]).decode('utf-8'),
            len(bytes(self)))


class Seckey(nacl.signing.SigningKey):
    @property
    def pubkey(self):
        return Pubkey(bytes(self.verify_key))

    def __str__(self):
        return 'Seckey<%s..%s (%d bytes)>' % (
            b64encode(bytes(self)[:6]).decode('utf-8'),
            b64encode(bytes(self)[-6:]).decode('utf-8'),
            len(bytes(self)))


class Enckey(bytes):
    @staticmethod
    def gen() -> 'Enckey':
        return Enckey(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))


sqlite3.register_adapter(Pubkey, Pubkey.sql_adapt)
sqlite3.register_converter('pubkey', Pubkey.sql_convert)
