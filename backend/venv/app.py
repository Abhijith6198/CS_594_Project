from flask import Flask, request, jsonify
from crypto.double_ratchet import DoubleRatchet
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import os
import sys
print(sys.path)


app = Flask(__name__)

# Example in-memory storage for simplicity
USERS = {}
SESSIONS = {}

@app.route('/register', methods=['POST'])
def register():
    user_id = request.json['user_id']
    if user_id in USERS:
        return jsonify({'error': 'User already exists'}), 409
    # Generate keys here (omitted for brevity, see X3DH implementation)
    def generate_key_pair():
    # Generate a private key for use in the exchange.
        private_key = x25519.X25519PrivateKey.generate()
        return private_key, private_key.public_key()

    USERS[user_id] = {
        'identity_key': 'identity_public_key',
        'signed_prekey': 'signed_prekey_public',
        'one_time_prekey': 'one_time_prekey_public'
    }
    return jsonify({'message': 'User registered', 'user_id': user_id}), 201

@app.route('/start_conversation', methods=['POST'])
def start_conversation():
    from_user = request.json['from_user']
    to_user = request.json['to_user']
    if to_user not in USERS:
        return jsonify({'error': 'Recipient not found'}), 404
    # Example shared secret initialization
    shared_secret = os.urandom(32)  # This should be derived from X3DH in practice
    session_id = f'{from_user}_{to_user}'
    SESSIONS[session_id] = DoubleRatchet(None, None)
    SESSIONS[session_id].initialize(shared_secret)
    return jsonify({'message': 'Conversation started', 'session_id': session_id}), 200

@app.route('/send_message', methods=['POST'])
def send_message():
    session_id = request.json['session_id']
    message = request.json['message']
    if session_id not in SESSIONS:
        return jsonify({'error': 'Session not found'}), 404
    encrypted_message = SESSIONS[session_id].encrypt(message)
    return jsonify({'encrypted_message': encrypted_message}), 200

@app.route('/receive_message', methods=['POST'])
def receive_message():
    session_id = request.json['session_id']
    encrypted_message = request.json['encrypted_message']
    if session_id not in SESSIONS:
        return jsonify({'error': 'Session not found'}), 404
    decrypted_message = SESSIONS[session_id].decrypt(encrypted_message)
    return jsonify({'decrypted_message': decrypted_message}), 200

if __name__ == '__main__':
    app.run(debug=True)
