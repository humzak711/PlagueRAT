from flask import render_template, Blueprint, request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64

encrypt_blueprint = Blueprint('encrypt', __name__)

# Function to encrypt messages
def encrypt_message(message: bytes, public_key: bytes) -> bytes:
    ''' Function to encrypt a message with a public key'''
    public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
    encrypted_message = public_key_obj.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message

@encrypt_blueprint.route('/encrypt/', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        try:
            # Get variables from the request
            message = request.form['message'].encode()
            public_key = request.form['public_key'].encode()

            # Remove whitespaces
            message = message.strip()
            public_key = public_key.strip()

            # Check if the message and public_key are not empty
            if not message or not public_key:
                return render_template('encrypt.html', ERROR='ERROR: Empty message or public key')

            # Return encrypted message to client as base64
            cipher_text = encrypt_message(message, public_key)
            cipher_text_base64 = base64.b64encode(cipher_text).decode()
            return render_template('encrypt.html', cipher_text=cipher_text_base64)

        # If message or public_key is invalid
        except Exception as e:
            print(e)
            return render_template('encrypt.html', ERROR='ERROR: Invalid message or public key')

    return render_template('encrypt.html')