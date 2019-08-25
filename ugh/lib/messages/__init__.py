import nacl
import json
# import time
from ..crypto import Seckey, Pubkey, Enckey
from enum import Enum
from typing import Union
from base64 import b64encode, b64decode

CUR_VERSION = 1


class MessageType(Enum):
    Stub = 'STUB'  # for testing purposes
    AccountReq = 'ACCOUNT_REQ'
    AccountResp = 'ACCOUNT_RESP'
    AccountCred = 'ACCOUNT_CRED'


class Message:
    @staticmethod
    def from_dict(d: dict):
        from ugh.lib.messages import account
        ty = MessageType(d['type'])
        del d['type']
        return {
            MessageType.Stub: lambda d:
                Stub.from_dict(d),
            MessageType.AccountReq: lambda d:
                account.AccountReq.from_dict(d),
            MessageType.AccountResp: lambda d:
                account.AccountResp.from_dict(d),
            MessageType.AccountCred: lambda d:
                account.AccountCred.from_dict(d),
        }[ty](d)

    def to_dict(self) -> dict:
        from ugh.lib.messages import account
        return {
            'version': CUR_VERSION,
            'type': {
                Stub: MessageType.Stub,
                account.AccountReq: MessageType.AccountReq,
                account.AccountResp: MessageType.AccountResp,
                account.AccountCred: MessageType.AccountCred,
            }[type(self)].value
        }


class SignedMessage:
    def __init__(self, msg_bytes: bytes, sig: bytes, pk: Pubkey):
        self.msg_bytes = msg_bytes
        self.sig = sig
        self.pk = pk

    @property
    def msg(self) -> Message:
        d = json.loads(self.msg_bytes.decode('utf-8'))
        # del d['sig_time']
        m = Message.from_dict(d)
        return m

    @staticmethod
    def sign(msg: Message, sk: Seckey) -> 'SignedMessage':
        d = msg.to_dict()
        # assert 'sig_time' not in d
        # d['sig_time'] = time.time()
        msg_bytes = json.dumps(d).encode('utf-8')
        sig = sk.sign(msg_bytes)
        return SignedMessage(sig.message, sig.signature, sk.pubkey)

    def verified_unwrap(self):
        if not self.is_valid():
            return False, None, None
        return True, self.msg, self.pk

    def is_valid(self):
        try:
            self.pk.verify(self.msg_bytes, self.sig)
        except nacl.exceptions.BadSignatureError:
            return False
        return True

    def __str__(self) -> str:
        return 'SignedMessage<{m} {pk} valid={v}>'.format(
            m=self.msg, pk=self.pk, v=self.is_valid())

    def __eq__(self, rhs) -> bool:
        return self.msg_bytes == rhs.msg_bytes \
            and self.sig == rhs.sig \
            and self.pk == rhs.pk

    def to_dict(self) -> dict:
        return {
            'msg': self.msg.to_dict(),
            'sig': b64encode(self.sig).decode('utf-8'),
            'pk': b64encode(bytes(self.pk)).decode('utf-8'),
        }

    @staticmethod
    def from_dict(d: dict) -> 'SignedMessage':
        msg_bytes = json.dumps(d['msg']).encode('utf-8')
        return SignedMessage(
            msg_bytes,
            b64decode(d['sig']),
            Pubkey(b64decode(d['pk'])))


class EncryptedMessage:
    def __init__(self, ctext_nonce: bytes):
        self.ctext_nonce = ctext_nonce

    @staticmethod
    def enc(
            msg: Union[Message, SignedMessage],
            k: Enckey) -> 'EncryptedMessage':
        d = msg.to_dict()
        msg_bytes = json.dumps(d).encode('utf-8')
        box = nacl.secret.SecretBox(k)
        return EncryptedMessage(box.encrypt(msg_bytes))

    def dec(self, k: Enckey) -> Union[Message, SignedMessage]:
        pass


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

    def __str__(self) -> str:
        return 'Stub<%d>' % (self.i,)
