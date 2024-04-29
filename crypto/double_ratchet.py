""" # file: double_ratchet.py
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

class DoubleRatchet:
    def __init__(self, dh_pair, dh_public):
        self.dh_pair = dh_pair
        self.dh_public = dh_public
        self.root_key = None
        self.chain_key = None
        self.next_chain_key = None
        self.skipped_keys = {}

    def initialize(self, shared_secret):
        # Initialize root key and chain key from shared secret
        self.root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'root_key',
            backend=default_backend()
        ).derive(shared_secret)
        
        self.chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chain_key',
            backend=default_backend()
        ).derive(shared_secret)

    def ratchet_step(self):
        # Simulate the ratchet step by deriving new chain keys
        self.next_chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'next_chain_key',
            backend=default_backend()
        ).derive(self.chain_key)
        self.chain_key = self.next_chain_key

    def encrypt(self, plaintext):
        from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
        from cryptography.hazmat.primitives import hashes
        from cryptography.fernet import Fernet
        key_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()
        ).derive(self.chain_key)
        key_fernet = base64.urlsafe_b64encode(key_bytes)
        f = Fernet(key_fernet)
        encrypted_message = f.encrypt(plaintext.encode())
        return encrypted_message

    def decrypt(self, encrypted_message):
        from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
        from cryptography.hazmat.primitives import hashes
        from cryptography.fernet import Fernet
        key_bytes = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'encryption',
            backend=default_backend()
        ).derive(self.chain_key)
        key_fernet = base64.urlsafe_b64encode(key_bytes)
        f = Fernet(key_fernet)
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()
 """

import base64
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class DoubleRatchet:
    def __init__(self, private_key_base64, public_key_base64):
        self.private_key = base64.b64decode(private_key_base64)
        self.public_key = base64.b64decode(public_key_base64)
        self.chain_key = None
        self.next_chain_key = None

    def initialize(self):
        # Example initialization logic
        self.chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'chain_key',
            backend=default_backend()
        ).derive(self.public_key + self.private_key)  # simplistic example

    def encrypt(self, plaintext):
        key_fernet = base64.urlsafe_b64encode(self.chain_key)
        f = Fernet(key_fernet)
        return f.encrypt(plaintext.encode()).decode()

    def decrypt(self, encrypted_message):
        key_fernet = base64.urlsafe_b64encode(self.chain_key)
        f = Fernet(key_fernet)
        return f.decrypt(encrypted_message.encode()).decode()

