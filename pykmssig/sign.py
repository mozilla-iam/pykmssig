import boto3
import json
import os

from pykmssig.hashes import get_digests
from pykmssig import settings

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

kms = boto3.client('kms')


def sign(ctxt={}, file_stream=None):

    digests = get_digests(file_stream)
    # Use the digest as plaintext
    # encrypt against the KMS key with optional context
    data_key = kms.generate_data_key(
        KeyId=settings.KMS_SIGNING_KEY,
        KeySpec='AES_256',
        EncryptionContext=ctxt
    )

    plaintext_key = data_key.get('Plaintext')
    ciphertext_key = data_key.get('CiphertextBlob')

    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(plaintext_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(
        json.dumps(digests).encode('utf-8')
    ) + encryptor.finalize()

    result = {
        'ciphertext': ciphertext,
        'ciphertext_key': ciphertext_key,
        'iv': iv,
        'tag': encryptor.tag

    }

    return result
