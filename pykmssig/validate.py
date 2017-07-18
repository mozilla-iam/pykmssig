import boto3
import json

from pykmssig.hashes import get_digests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

kms = boto3.client('kms')


def verify(ctxt={}, file_stream=None, sigs_b=None):
    """Signature verification function.

    :ctxt encryption context
    :file stream the file to compare with the stream
    :signature
        :ciphertext: encrypted payload
        :ciphertext_key: encrypted KMS derived key
        :iv: AES initialization vector used to encrypt payload
        :tag: AES GCM authentication code
    """
    sigs_a = get_digests(file_stream)

    # Decrypt the signature using the KMS Key using the optional context

    plaintext_key = kms.decrypt(
        CiphertextBlob=sigs_b['ciphertext_key'],
        EncryptionContext=ctxt
    ).get('Plaintext')

    decryptor = Cipher(
        algorithms.AES(plaintext_key),
        modes.GCM(sigs_b['iv'], sigs_b['tag']),
        backend=default_backend()
    ).decryptor()

    sigs_b = json.loads(
        decryptor.update(
            sigs_b['ciphertext']
        ) + decryptor.finalize()
    )

    if sigs_a == sigs_b:
        return {
            'status': 'valid',
            'sigs_a': sigs_a,
            'sigs_b': sigs_b
        }
    else:
        return {
            'status': 'invalid',
            'sigs_a': sigs_a,
            'sigs_b': sigs_b
        }
