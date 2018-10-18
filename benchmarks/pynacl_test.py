import pytest
from nacl.bindings import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
from nacl.encoding import HexEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import SignedMessage, SigningKey, VerifyKey
#from utils import assert_equal, assert_not_equal, read_crypto_test_vectors
#from nacl import *
import nacl

print(dir(nacl))


# from __future__ import absolute_import, division, print_function
#
# import binascii
#
# import pytest
#
# #from utils import assert_equal, assert_not_equal, read_crypto_test_vectors
# import read_crypto_test_vectors
#
# from nacl.bindings import crypto_sign_PUBLICKEYBYTES, crypto_sign_SEEDBYTES
# from nacl.encoding import HexEncoder
# from nacl.exceptions import BadSignatureError
# from nacl.signing import SignedMessage, SigningKey, VerifyKey
#
#
# def tohex(b):
#     return binascii.hexlify(b).decode('ascii')
#
#
# def ed25519_known_answers():
#     # Known answers taken from: http://ed25519.cr.yp.to/python/sign.input
#     # hex-encoded fields on each input line: sk||pk, pk, msg, signature||msg
#     # known answer fields: sk, pk, msg, signature, signed
#     DATA = "ed25519"
#     lines = read_crypto_test_vectors(DATA, delimiter=b':')
#     return [(x[0][:64],   # secret key
#              x[1],        # public key
#              x[2],        # message
#              x[3][:128],  # signature
#              x[3],        # signed message
#              )
#             for x in lines]
#
#
# class TestSigningKey:
#     def test_initialize_with_generate(self):
#         SigningKey.generate()
#
#     def test_wrong_length(self):
#         with pytest.raises(ValueError):
#             SigningKey(b"")
#
#     def test_bytes(self):
#         k = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert bytes(k) == b"\x00" * crypto_sign_SEEDBYTES
#
#     def test_equal_keys_are_equal(self):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert_equal(k1, k1)
#         assert_equal(k1, k2)
#
#     def test_equal_keys_have_equal_hashes(self):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         k2 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert hash(k1) == hash(k2)
#         assert id(k1) != id(k2)
#
#     @pytest.mark.parametrize('k2', [
#         b"\x00" * crypto_sign_SEEDBYTES,
#         SigningKey(b"\x01" * crypto_sign_SEEDBYTES),
#         SigningKey(b"\x00" * (crypto_sign_SEEDBYTES - 1) + b"\x01"),
#     ])
#     def test_different_keys_are_not_equal(self, k2):
#         k1 = SigningKey(b"\x00" * crypto_sign_SEEDBYTES)
#         assert_not_equal(k1, k2)
#
#     @pytest.mark.parametrize("seed", [
#         b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
#     ])
#     def test_initialization_with_seed(self, seed):
#         SigningKey(seed, encoder=HexEncoder)
#
#     @pytest.mark.parametrize(
#         ("seed", "_public_key", "message", "signature", "expected"),
#         ed25519_known_answers()
#     )
#     def test_message_signing(self, seed, _public_key,
#                              message, signature, expected):
#         signing_key = SigningKey(
#             seed,
#             encoder=HexEncoder,
#         )
#         signed = signing_key.sign(
#             binascii.unhexlify(message),
#             encoder=HexEncoder,
#         )
#
#         assert signed == expected
#         assert signed.message == message
#         assert signed.signature == signature
#
#
class TestVerifyKey:
    def test_wrong_length(self):
        with pytest.raises(ValueError):
            VerifyKey(b"")

    def test_bytes(self):
        k = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        assert bytes(k) == b"\x00" * crypto_sign_PUBLICKEYBYTES

    def test_equal_keys_are_equal(self):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        #assert_equal(k1, k1)
        #assert_equal(k1, k2)

    def test_equal_keys_have_equal_hashes(self):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        k2 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        #assert hash(k1) == hash(k2)
        #assert id(k1) != id(k2)

    @pytest.mark.parametrize('k2', [
        b"\x00" * crypto_sign_PUBLICKEYBYTES,
        VerifyKey(b"\x01" * crypto_sign_PUBLICKEYBYTES),
        VerifyKey(b"\x00" * (crypto_sign_PUBLICKEYBYTES - 1) + b"\x01"),
    ])
    def test_different_keys_are_not_equal(self, k2):
        k1 = VerifyKey(b"\x00" * crypto_sign_PUBLICKEYBYTES)
        #assert_not_equal(k1, k2)

    @pytest.mark.parametrize(
        ("_seed", "public_key", "message", "signature", "signed"),
#        ed25519_known_answers()
    )
    def test_valid_signed_message(
            self, _seed, public_key, message, signature, signed):
        key = VerifyKey(
            public_key,
            encoder=HexEncoder,
        )

        assert binascii.hexlify(
            key.verify(signed, encoder=HexEncoder),
        ) == message
        assert binascii.hexlify(
            key.verify(message, signature, encoder=HexEncoder),
        ) == message

    def test_invalid_signed_message(self):
        skey = SigningKey.generate()
        smessage = skey.sign(b"A Test Message!")
        signature, message = smessage.signature, b"A Forged Test Message!"

        # Small sanity check
        assert skey.verify_key.verify(smessage)

        with pytest.raises(BadSignatureError):
            skey.verify_key.verify(message, signature)

        with pytest.raises(BadSignatureError):
            forged = SignedMessage(signature + message)
            skey.verify_key.verify(forged)

    def test_key_conversion(self):
        keypair_seed = (b"421151a459faeade3d247115f94aedae"
                        b"42318124095afabe4d1451a559faedee")
        signing_key = SigningKey(binascii.unhexlify(keypair_seed))
        verify_key = signing_key.verify_key

        private_key = bytes(signing_key.to_curve25519_private_key())
        public_key = bytes(verify_key.to_curve25519_public_key())

        assert tohex(private_key) == ("8052030376d47112be7f73ed7a019293"
                                      "dd12ad910b654455798b4667d73de166")

        assert tohex(public_key) == ("f1814f0e8ff1043d8a44d25babff3ced"
                                     "cae6c22c3edaa48f857ae70de2baae50")


# def check_type_error(expected, f, *args):
#     with pytest.raises(TypeError) as e:
#         f(*args)
#     assert expected in str(e)
#
#
# def test_wrong_types():
#     sk = SigningKey.generate()
#
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, 12)
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, sk)
#     check_type_error("SigningKey must be created from a 32 byte seed",
#                      SigningKey, sk.verify_key)
#
#     check_type_error("VerifyKey must be created from 32 bytes",
#                      VerifyKey, 13)
#     check_type_error("VerifyKey must be created from 32 bytes",
#                      VerifyKey, sk)
#     check_type_error("VerifyKey must be created from 32 bytes",
# VerifyKey, sk.verify_key)


skey = SigningKey.generate()
skey2 = SigningKey.generate()
smessage = skey.sign(b"A Test Message!" * 1000)
smessage2 = skey2.sign(b"A Test Message!" * 1000)
signature, message = smessage.signature, b"A Forged Test Message!"

import time
start = time.time()
duration_secs = 1
count = 0
while time.time() - start < duration_secs:
    assert skey.verify_key.verify(smessage)
    count += 1
print('%s NACL.time_verify sigs verified within %s secs' % (count, duration_secs))
##assert skey.verify_key.verify(smessage2)
sig_key = skey._signing_key
ver_key = skey.verify_key._key
prv_key = skey.to_curve25519_private_key()._private_key
pub_key = skey.to_curve25519_private_key().public_key._public_key
##print("Len: Sig %s, Ver %s, prk %s, pbk %s" % len(sig_key), len(ver_key), len(prv_key), len(pub_key))

from nacl.bindings import crypto_box_PUBLICKEYBYTES, crypto_box_SECRETKEYBYTES
from nacl.public import Box, PrivateKey, PublicKey
from nacl.utils import random
pbk = PublicKey(b"\x00" * crypto_box_PUBLICKEYBYTES)
prk = PrivateKey(b"\x00" * crypto_box_SECRETKEYBYTES)
print(prk, prk.public_key, pbk)
prk1 = PrivateKey(b"\x01" * crypto_box_SECRETKEYBYTES),
prk2 = PrivateKey(b"\x01" * crypto_box_SECRETKEYBYTES),
##assert prk1 != prk2
prk3 = PrivateKey(b"\x00" * (crypto_box_SECRETKEYBYTES - 1) + b"\x01")
print(prk1, prk2, prk3)

alices = PrivateKey.generate()
alice_pbk = alices.public_key
bobes = PrivateKey.generate()
bob_pbk = alices.public_key
print(alice_pbk, bob_pbk)
assert alice_pbk != bob_pbk