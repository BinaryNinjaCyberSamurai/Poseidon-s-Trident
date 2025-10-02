import pytest
from src import encryption

def test_encrypt_decrypt_roundtrip():
    key = encryption.generate_key()
    message = "hacktoberfest"
    token = encryption.encrypt_message(message, key)
    decrypted = encryption.decrypt_message(token, key)
    assert decrypted == message