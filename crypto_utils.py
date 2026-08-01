import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend


def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode('utf-8'))
    return key, salt


def encrypt_private_key(private_pem, password):
    key, salt = derive_key_from_password(password)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, private_pem.encode('utf-8'), None)
    result = salt + nonce + encrypted
    return base64.b64encode(result).decode('utf-8')


def decrypt_private_key(encrypted_key_b64, password):
    data = base64.b64decode(encrypted_key_b64)
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    key, _ = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode('utf-8')


def generate_ecc_keypair(password=None):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_key_str = private_pem.decode('utf-8')
    
    if password:
        private_key_str = encrypt_private_key(private_key_str, password)
    
    return private_key_str, public_pem.decode('utf-8')


def load_private_key(private_pem):
    return serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )


def load_public_key(public_pem):
    return serialization.load_pem_public_key(
        public_pem.encode('utf-8'),
        backend=default_backend()
    )


def derive_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ip-protection-system',
        backend=default_backend()
    ).derive(shared_key)
    return derived_key


def encrypt_file(file_data, sender_private_pem, receiver_public_pem):
    sender_private_key = load_private_key(sender_private_pem)
    receiver_public_key = load_public_key(receiver_public_pem)
    
    shared_key = derive_shared_key(sender_private_key, receiver_public_key)
    
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    
    encrypted_data = aesgcm.encrypt(nonce, file_data, None)
    
    result = nonce + encrypted_data
    return base64.b64encode(result).decode('utf-8')


def decrypt_file(encrypted_data_b64, receiver_private_pem, sender_public_pem):
    receiver_private_key = load_private_key(receiver_private_pem)
    sender_public_key = load_public_key(sender_public_pem)
    
    shared_key = derive_shared_key(receiver_private_key, sender_public_key)
    
    encrypted_data = base64.b64decode(encrypted_data_b64)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    
    aesgcm = AESGCM(shared_key)
    decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
    
    return decrypted_data


def encrypt_with_system_key(file_data, system_public_pem, sender_private_pem):
    return encrypt_file(file_data, sender_private_pem, system_public_pem)


def decrypt_with_system_key(encrypted_data_b64, system_private_pem, sender_public_pem):
    return decrypt_file(encrypted_data_b64, system_private_pem, sender_public_pem)


def sign_data(data, private_pem):
    private_key = load_private_key(private_pem)
    signature = private_key.sign(
        data if isinstance(data, bytes) else data.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(data, signature_b64, public_pem):
    public_key = load_public_key(public_pem)
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            data if isinstance(data, bytes) else data.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False
