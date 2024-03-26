from flask import render_template, Blueprint, request
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64


decrypt_blueprint = Blueprint('decrypt', __name__)

# Function to decrypt messages
def decrypt_message(cipher_text: bytes, private_key: bytes) -> str:
    ''' Function to decrypt an encrypted UTF-8 encoded string '''
    private_key_obj = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    decrypted_message = private_key_obj.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_message.decode()

@decrypt_blueprint.route('/decrypt/', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        try:
            # Get variables from request
            cipher_text_base64 = request.form['cipher_text']
            private_key = request.form['private_key'].encode()

            # Remove whitespaces
            cipher_text_base64 = cipher_text_base64.strip()
            private_key = private_key.strip()

            # Check if cipher_text and private_key are not empty
            if not cipher_text_base64 or not private_key:
                return render_template('decrypt.html', ERROR='ERROR: Empty cipher text or private key')

            # Decode base64 and decrypt message
            cipher_text = base64.b64decode(cipher_text_base64)
            decoded_text = decrypt_message(cipher_text, private_key)
            return render_template('decrypt.html', decoded_text=decoded_text)

        # If cipher_text or private_key is invalid
        except Exception as e:
            print(e)
            return render_template('decrypt.html', ERROR='ERROR: Invalid cipher text or private key')

    return render_template('decrypt.html')