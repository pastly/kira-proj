import nacl
import json
from base64 import b64encode
from ..user import Seckey, Pubkey
from enum import Enum

CUR_VERSION = 1


class MessageType(Enum):
    Stub = 'STUB'  # for testing purposes
    AccountReq = 'ACCOUNT_REQ'
    AccountResp = 'ACCOUNT_RESP'


class Message:
    @staticmethod
    def from_dict(d: dict):
        from ugh.lib.messages import account
        ty = MessageType(d['type'])
        del d['type']
        return {
            MessageType.AccountReq: lambda d:
                account.AccountReq.from_dict(d),
            MessageType.AccountResp: lambda d:
                account.AccountResp.from_dict(d),
            MessageType.Stub: lambda d:
                Stub.from_dict(d),
        }[ty](d)

    def to_dict(self) -> dict:
        from .account import AccountReq, AccountResp
        return {
            'version': CUR_VERSION,
            'type': {
                AccountReq: MessageType.AccountReq,
                AccountResp: MessageType.AccountResp,
                Stub: MessageType.Stub,
            }[type(self)].value
        }


class SignedMessage:
    def __init__(self, msg: bytes, sig: bytes, pk: Pubkey):
        self.msg = msg
        self.sig = sig
        self.pk = pk

    @staticmethod
    def sign(msg: Message, sk: Seckey) -> 'SignedMessage':
        m = json.dumps(msg.to_dict()).encode('utf-8')
        sig = sk.sign(m)
        return SignedMessage(sig.message, sig.signature, sk.pubkey)

    def verified_unwrap(self):
        try:
            self.pk.verify(self.msg, self.sig)
        except nacl.exceptions.BadSignatureError:
            return False, None, None
        return True, \
            Message.from_dict(json.loads(self.msg.decode('utf-8'))), \
            self.pk

    def to_json_str(self) -> str:
        return json.dumps({
            'msg': b64encode(self.msg),
            'sig': b64encode(self.sig),
            'pk': b64encode(bytes(self.pk)),
        })


class Stub(Message):
    def __init__(self, i):
        self.i = i

    def to_dict(self) -> dict:
        d = {'i': self.i}
        d.update(super().to_dict())
        return d

    @staticmethod
    def from_dict(d: dict) -> 'Stub':
        return Stub(d['i'])
