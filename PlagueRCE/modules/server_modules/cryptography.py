import hashlib
import base64
from typing import Tuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


class cryptography_toolkit:
    ''' 
    Ready made toolkit for RSA cryptography 
    and deterministic hashing
    '''
    
    def __init__(self, bytesize: int=1024) -> None:
        ''' Class Initializer '''
        self.bytesize: int = bytesize

    # Function to hash data
    def hash_message(message: str) -> hash:
        ''' Hashes message in a way which is designed to be deterministic '''

        hashed_message: hash = hashlib.sha256(message.encode()).hexdigest()
        return hashed_message

    # Function to generate key pair
    def generate_key_pair(keysize: int=4096) -> Tuple[bytes, bytes]:
        ''' Function to generate a RSA key pair '''

        private_key = rsa.generate_private_key(
           public_exponent=65537,
            key_size=keysize,
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
    
    # Function to decrypt messages
    def decrypt_message(cipher_text: base64, private_key: str) -> str:
        ''' Function to decrypt an encrypted UTF-8 encoded string '''

        # Format parameters
        cipher_text: bytes = base64.b64decode(cipher_text)
        private_key: bytes = private_key.encode()

        cipher_text: bytes = cipher_text.strip()
        private_key: bytes = private_key.strip()
        
        # Decrypt the message using private key
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
    
    # Function to encrypt messages 
    def encrypt_message(message: str, public_key: str) -> base64:
        ''' Function to encrypt a message with a public key'''

        # Format parameters
        message: bytes = message.encode()
        public_key: bytes = public_key.encode()

        message: bytes = message.strip()
        public_key: bytes = public_key.strip()
        
        # Encrypt the message using public key
        public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
        encrypted_message = public_key_obj.encrypt(
        message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted_message).decode()