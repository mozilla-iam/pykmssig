import base64
import boto3
import os

from hashlib import sha512
from pykmssig import settings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

kms = boto3.client('kms')


def sign(ctxt={}, file_stream=None):
    # Hash the file stream using sha-512
    h = sha512()

    b_file_stream = base64.b64encode(file_stream.encode())
    h.update(b_file_stream)

    # return a digest of the hash
    digest = h.digest()

    # Use the digest as plaintext
    # encrypt against the KMS key with optional context
    data_key = kms.generate_data_key(
        KeyId=settings.KMS_SIGNING_KEY,
        KeySpec='AES_256',
        EncryptionContext=ctxt
    )

    plaintext_key = data_key.get('Plaintext')
    ciphertext_key = data_key.get('CiphertextBlob')

    print(base64.b64encode(ciphertext_key))

    print(base64.b64encode(plaintext_key))

    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(plaintext_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(digest) + encryptor.finalize()

    return {
        'ciphertext': ciphertext,
        'ciphertext_key': ciphertext_key,
        'iv': iv,
        'tag': encryptor.tag

    }
