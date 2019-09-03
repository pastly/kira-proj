import nacl
import json
# import time
from ..crypto import Seckey, Pubkey, Enckey
from enum import Enum
from typing import Union, Tuple, Optional
from base64 import b64encode, b64decode
import logging


log = logging.getLogger(__name__)
CUR_VERSION = 1


class MessageErr(Enum):
    pass


class SignedMessageErr(MessageErr):
    BadSig = 'The signature is invalid'
    UnknownUser = 'The pubkey that signed this request is unknown'


class CredErr(MessageErr):
    Malformed = 'Message was not a valid AccountCred'
    BadCred = 'AccountCred is not valid right now or wasn\'t made by us'
    WrongUser = 'AccountCred is for a user other than the expected one'


class MessageType(Enum):
    Stub = 'STUB'  # for testing purposes
    SignedMessage = 'SIGNED_MESSAGE'  # not a subclass of Message
    EncryptedMessage = 'ENCRYPTED_MESSAGE'  # not a subclass of Message
    AccountReq = 'ACCOUNT_REQ'
    AuthResp = 'ACCOUNT_RESP'
    AccountCred = 'ACCOUNT_CRED'
    AuthReq = 'AUTH_REQ'
    AuthChallenge = 'AUTH_CHALLENGE'
    AuthChallengeResp = 'AUTH_CHALLENGE_RESP'
    LocationUpdate = 'LOCATION_UPDATE'
    LocationUpdateResp = 'LOCATION_UPDATE_RESP'
    GetInfo = 'GET_INFO'
    GetInfoLocation = 'GET_INFO_LOCATION'
    GetInfoResp = 'GET_INFO_RESP'
    GetInfoRespLocation = 'GET_INFO_RESP_LOCATION'


class Message:
    @staticmethod
    def from_dict(d: dict) -> Optional['Message']:
        from rela.lib.messages import account, location, getinfo
        ty = MessageType(d['type'])
        del d['type']
        return {  # type: ignore
            MessageType.Stub: lambda d:
                Stub.from_dict(d),
            MessageType.SignedMessage: lambda d:
                SignedMessage.from_dict(d),
            MessageType.EncryptedMessage: lambda d:
                EncryptedMessage.from_dict(d),
            MessageType.AccountReq: lambda d:
                account.AccountReq.from_dict(d),
            MessageType.AuthResp: lambda d:
                account.AuthResp.from_dict(d),
            MessageType.AccountCred: lambda d:
                account.AccountCred.from_dict(d),
            MessageType.AuthReq: lambda d:
                account.AuthReq.from_dict(d),
            MessageType.AuthChallenge: lambda d:
                account.AuthChallenge.from_dict(d),
            MessageType.AuthChallengeResp: lambda d:
                account.AuthChallengeResp.from_dict(d),
            MessageType.LocationUpdate: lambda d:
                location.LocationUpdate.from_dict(d),
            MessageType.LocationUpdateResp: lambda d:
                location.LocationUpdateResp.from_dict(d),
            MessageType.GetInfo: lambda d:
                getinfo.GetInfo.from_dict(d),
            MessageType.GetInfoLocation: lambda d:
                getinfo.GetInfoLocation.from_dict(d),
            MessageType.GetInfoResp: lambda d:
                getinfo.GetInfoResp.from_dict(d),
            MessageType.GetInfoRespLocation: lambda d:
                getinfo.GetInfoRespLocation.from_dict(d),
        }[ty](d)

    def to_dict(self) -> dict:
        from rela.lib.messages import account, location, getinfo
        return {
            'version': CUR_VERSION,
            'type': {
                Stub: MessageType.Stub,
                account.AccountReq: MessageType.AccountReq,
                account.AuthResp: MessageType.AuthResp,
                account.AccountCred: MessageType.AccountCred,
                account.AuthReq: MessageType.AuthReq,
                account.AuthChallenge: MessageType.AuthChallenge,
                account.AuthChallengeResp: MessageType.AuthChallengeResp,
                location.LocationUpdate: MessageType.LocationUpdate,
                location.LocationUpdateResp: MessageType.LocationUpdateResp,
                getinfo.GetInfo: MessageType.GetInfo,
                getinfo.GetInfoLocation: MessageType.GetInfoLocation,
                getinfo.GetInfoResp: MessageType.GetInfoResp,
                getinfo.GetInfoRespLocation: MessageType.GetInfoRespLocation,
            }[type(self)].value
        }

    def __eq__(self, rhs) -> bool:
        # Message has no members of its own, so only check that type is same
        return isinstance(rhs, Message)


class SignedMessage:
    def __init__(self, msg_bytes: bytes, sig: bytes, pk: Pubkey):
        self.msg_bytes = msg_bytes
        self.sig = sig
        self.pk = pk

    @property
    def msg(self) -> Optional[Message]:
        assert self.is_valid()
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

    def unwrap(self) -> Tuple[Optional[Message], Pubkey]:
        assert self.is_valid()
        return self.msg, self.pk

    def is_valid(self) -> bool:
        try:
            self.pk.verify(self.msg_bytes, self.sig)
        except nacl.exceptions.BadSignatureError:  # type: ignore
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
            'version': CUR_VERSION,
            'type': MessageType.SignedMessage.value,
            'msg': b64encode(self.msg_bytes).decode('utf-8'),
            'sig': b64encode(self.sig).decode('utf-8'),
            'pk': b64encode(bytes(self.pk)).decode('utf-8'),
        }

    @staticmethod
    def from_dict(d: dict) -> 'SignedMessage':
        return SignedMessage(
            b64decode(d['msg']),
            b64decode(d['sig']),
            Pubkey(b64decode(d['pk'])))


class EncryptedMessage:
    def __init__(self, ctext_nonce: bytes):
        self.ctext_nonce = ctext_nonce

    @staticmethod
    def enc(
            msg: Union[Message, SignedMessage, 'EncryptedMessage'],
            k: Enckey) -> 'EncryptedMessage':
        d = msg.to_dict()
        msg_bytes = json.dumps(d).encode('utf-8')
        box = nacl.secret.SecretBox(k)
        return EncryptedMessage(box.encrypt(msg_bytes))

    def try_dec(
            self, k: Enckey) -> \
            Optional[Union[Message, SignedMessage, 'EncryptedMessage']]:
        ''' Like dec(...), but returns None instead of allowing exception to
        bubble up '''
        b = nacl.secret.SecretBox(k)
        try:
            b.decrypt(self.ctext_nonce)
        except (
                nacl.exceptions.CryptoError,  # type: ignore
                nacl.exceptions.ValueError):  # type: ignore
            return None
        else:
            return self.dec(k)

    def dec(
            self, k: Enckey) -> \
            Optional[Union[Message, SignedMessage, 'EncryptedMessage']]:
        ''' Like try_dec(...) but doesn't check for decryption failure
        exceptions '''
        b = nacl.secret.SecretBox(k)
        msg_bytes = b.decrypt(self.ctext_nonce)
        d = json.loads(msg_bytes)
        return Message.from_dict(d)

    @staticmethod
    def from_dict(d: dict) -> Optional['EncryptedMessage']:
        try:
            ctext_nonce = b64decode(d['ctext_nonce'])
            log.warning(
                '%s no ctext_nonce in dict',
                EncryptedMessage.from_dict.__name__)
            return EncryptedMessage(ctext_nonce)
        except KeyError:
            return None

    def to_dict(self) -> dict:
        return {
            'version': CUR_VERSION,
            'type': MessageType.EncryptedMessage.value,
            'ctext_nonce': b64encode(bytes(self.ctext_nonce)).decode('utf-8'),
        }

    def __eq__(self, rhs) -> bool:
        return self.ctext_nonce == rhs.ctext_nonce

    def __str__(self) -> str:
        return 'EncryptedMessage<ctext_nonce=[%d bytes]>' % \
            (len(self.ctext_nonce),)


class Stub(Message):
    def __init__(self, i: int):
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

    def __eq__(self, rhs) -> bool:
        if not isinstance(rhs, Stub):
            return False
        return self.i == rhs.i
