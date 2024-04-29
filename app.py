from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
# from double_ratchet import DoubleRatchet
# from crypto.double_ratchet import DoubleRatchet
import base64
import sys
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from datetime import datetime
sys.path.append(r'C:/Users/snethi4/Desktop/CS_594_Project/mySecureApp/crypto')
import sys
print(sys.path)
sys.path.append('C:/Users/snethi4/Desktop/CS_594_Project/mySecureApp/crypto')  # Adjust path as necessary


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mySecureApp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)  # Stores encrypted messages
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message from {self.sender_id} to {self.recipient_id}>'

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    public_key = db.Column(db.String(), unique=True, nullable=False)
    private_key = db.Column(db.String(), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

with app.app_context():
    db.create_all()

    

@app.route('/')
def home():
    return render_template('index.html')

""" @app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({'error': 'Username already taken'}), 409

    # Generate user keys
    private_key, public_key = generate_key_pair()
    user = User(username=username, public_key=public_key, private_key=private_key)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully', 'username': username}), 201 """

@app.route('/register', methods=['POST'])
def register():
    username = request.json['username']
    public_key = request.json['public_key']
    private_key = request.json['private_key']
    new_user = User(username=username, public_key=public_key, private_key=private_key)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/messages/<int:user_id>', methods=['GET'])
def get_messages_for_user(user_id):
    messages = Message.query.filter_by(recipient_id=user_id).all()
    return jsonify({'messages': [str(message) for message in messages]})



@app.route('/send_message', methods=['POST'])
def send_message():
    sender_username = request.json['sender']
    recipient_username = request.json['recipient']
    message = request.json['message']

    sender = User.query.filter_by(username=sender_username).first()
    recipient = User.query.filter_by(username=recipient_username).first()

    if not sender or not recipient:
        return jsonify({'error': 'Invalid user information'}), 404

    # Encrypt the message
    encrypted_message = sender.encrypt(message)

    # Create and store the message
    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, content=encrypted_message)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Message sent successfully'}), 200


@app.route('/get_messages', methods=['POST'])
def get_messages_by_username():
    username = request.json['username']
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    messages = Message.query.filter_by(recipient_id=user.id).all()
    return jsonify({'messages': [message.content for message in messages]})


@app.route('/receive_message', methods=['POST'])
def receive_message():
    session_id = request.json['session_id']
    encrypted_message = request.json['encrypted_message']

    # Decryption process (this is illustrative; you'd have more context in real use)
    decrypted_message = dr.decrypt(encrypted_message)
    return jsonify({'decrypted_message': decrypted_message}), 200

def generate_key_pair():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return base64.b64encode(private_bytes).decode('utf-8'), base64.b64encode(public_bytes).decode('utf-8')

if __name__ == '__main__':
    app.run(debug=True)


