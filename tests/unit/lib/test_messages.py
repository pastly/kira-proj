from ugh.lib.messages import Stub, SignedMessage, EncryptedMessage
from ugh.lib.crypto import Seckey, Enckey


SK = Seckey((28379873947).to_bytes(32, byteorder='big'))
EK = Enckey.gen()


def test_signedmessage_dict_identity():
    first = SignedMessage.sign(Stub(420), SK)
    second = SignedMessage.from_dict(first.to_dict())
    assert first == second


def test_encryptmessage_dict_identity_1():
    first = EncryptedMessage.enc(Stub(420), EK)
    second = EncryptedMessage.from_dict(first.to_dict())
    assert first == second


def test_encryptmessage_dict_identity_2():
    first = EncryptedMessage.enc(SignedMessage.sign(Stub(420), SK), EK)
    second = EncryptedMessage.from_dict(first.to_dict())
    assert first == second


def test_encryptmessage_dict_identity_3():
    ek_sub = Enckey.gen()
    first = EncryptedMessage.enc(EncryptedMessage.enc(Stub(420), ek_sub), EK)
    second = EncryptedMessage.from_dict(first.to_dict())
    assert first == second


def test_encryptedmessage_crypt_identity_1():
    # EncryptedMessage can store a Message
    m_in = Stub(29873987)
    m_out = EncryptedMessage.enc(m_in, EK).dec(EK)
    assert m_in == m_out


def test_encryptedmessage_crypt_identity_2():
    # EncryptedMessage can store a SignedMessage
    m_in = SignedMessage.sign(Stub(29874987), SK)
    m_out = EncryptedMessage.enc(m_in, EK).dec(EK)
    assert m_in == m_out


def test_encryptedmessage_crypt_identity_3():
    # EncryptedMessage can store a EncryptedMessage, though at the time of
    # writing, there's no need for this. It's just for completeness
    ek_sub = Enckey.gen()
    m_in = EncryptedMessage.enc(Stub(29874), ek_sub)
    m_out = EncryptedMessage.enc(m_in, EK).dec(EK)
    assert m_in == m_out
