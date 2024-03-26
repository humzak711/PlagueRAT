from flask import render_template, Blueprint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from typing import Tuple

generate_blueprint = Blueprint('generate', __name__)

# Function to generate key pair
def generate_key_pair() -> Tuple[bytes, bytes]:
    ''' Function to generate a 2048 bit RSA key pair '''
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize keys to bytes for rendering into html template
    private_key_bytes: bytes = private_key.private_bytes(
                                   encoding=serialization.Encoding.PEM,
                                   format=serialization.PrivateFormat.PKCS8,
                                   encryption_algorithm=serialization.NoEncryption()
                                   ).decode()
    public_key_bytes: bytes =  public_key.public_bytes(
                                   encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo
                                   ).decode()

    return private_key_bytes, public_key_bytes

@generate_blueprint.route('/generate/', methods=['GET'])
def generate(): 
    
    # Generate key pair 
    private_key, public_key = generate_key_pair()

    return render_template('generate.html', private_key=private_key, public_key=public_key)