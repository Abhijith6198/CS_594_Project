from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

def generate_key_pair():
    # Generate a private key for use in the exchange.
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()

def serialize_key(public_key):
    # Serialize a public key to bytes
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

def deserialize_key(public_bytes):
    # Deserialize a public key from bytes
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)

def calculate_shared_secret(private_key, public_key):
    # Calculate the shared secret
    return private_key.exchange(public_key)

# Generate keys for Alice
alice_identity_private, alice_identity_public = generate_key_pair()
alice_signed_prekey_private, alice_signed_prekey_public = generate_key_pair()
alice_one_time_prekey_private, alice_one_time_prekey_public = generate_key_pair()

# Generate keys for Bob
bob_identity_private, bob_identity_public = generate_key_pair()
bob_signed_prekey_private, bob_signed_prekey_public = generate_key_pair()
bob_one_time_prekey_private, bob_one_time_prekey_public = generate_key_pair()

# Simulate the exchange of public keys
# Alice receives Bob's public keys and vice versa
alice_sees_bob = {
    "identity": bob_identity_public,
    "signed_prekey": bob_signed_prekey_public,
    "one_time_prekey": bob_one_time_prekey_public
}

bob_sees_alice = {
    "identity": alice_identity_public,
    "signed_prekey": alice_signed_prekey_public,
    "one_time_prekey": alice_one_time_prekey_public
}

# Calculate shared secrets
# DH1: Alice's identity key with Bob's signed prekey
# DH2: Alice's signed prekey with Bob's identity key
# DH3: Alice's signed prekey with Bob's signed prekey
# DH4: Alice's one-time prekey with Bob's signed prekey (optional, for added forward secrecy)
dh1 = calculate_shared_secret(alice_identity_private, alice_sees_bob["signed_prekey"])
dh2 = calculate_shared_secret(alice_signed_prekey_private, alice_sees_bob["identity"])
dh3 = calculate_shared_secret(alice_signed_prekey_private, alice_sees_bob["signed_prekey"])
dh4 = calculate_shared_secret(alice_one_time_prekey_private, alice_sees_bob["signed_prekey"])

# Concatenate and hash the shared secrets to derive the master secret
from hashlib import sha256
master_secret = sha256(dh1 + dh2 + dh3 + dh4).digest()

print("Master Secret:", master_secret.hex())
