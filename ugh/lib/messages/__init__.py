import json
from base64 import b64encode
from nacl.signing import SigningKey
from enum import Enum

CUR_VERSION = 1


class MessageType(Enum):
    AccountReq = 'ACCOUNT_REQ'
    AccountResp = 'ACCOUNT_RESP'


class Message:
    @staticmethod
    def from_dict(d: dict):
        from .account import AccountReq
        ty = MessageType(d['type'])
        del d['type']
        return {
            MessageType.AccountReq: AccountReq.from_dict(d),
        }[ty]

    def to_dict(self) -> dict:
        from .account import AccountReq, AccountResp
        return {
            'version': CUR_VERSION,
            'type': {
                AccountReq: MessageType.AccountReq,
                AccountResp: MessageType.AccountResp,
            }[type(self)].value
        }
        raise NotImplementedError()


class SignedMessage:
    def __init__(self, msg: bytes, sig: bytes):
        self.msg = msg
        self.sig = sig

    @staticmethod
    def sign_message(msg: Message, sk: SigningKey):
        m = json.dumps(msg.to_dict()).encode('utf-8')
        sig = sk.sign(m)
        return SignedMessage(m, sig)

    def to_json_str(self) -> str:
        return json.dumps({
            'msg': b64encode(self.msg),
            'sig': b64encode(self.sig),
        })
