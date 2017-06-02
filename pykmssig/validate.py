import base64
import boto3

from hashlib import sha512

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

kms = boto3.client('kms')


def verify(ctxt={}, file_stream=None, signature=None):
    """Signature verification function.

    :ctxt encryption context
    :file stream the file to compare with the stream
    :signature
        :ciphertext: encrypted payload
        :ciphertext_key: encrypted KMS derived key
        :iv: AES initialization vector used to encrypt payload
        :tag: AES GCM authentication code
    """
    h = sha512()

    b_file_stream = base64.b64encode(file_stream.encode())
    h.update(b_file_stream)

    # return a digest of the hash
    digest = h.digest()

    # Decrypt the signature using the KMS Key using the optional context

    plaintext_key = kms.decrypt(
        CiphertextBlob=signature['ciphertext_key'],
        EncryptionContext=ctxt
    ).get('Plaintext')

    decryptor = Cipher(
        algorithms.AES(plaintext_key),
        modes.GCM(signature['iv'], signature['tag']),
        backend=default_backend()
    ).decryptor()

    signature = decryptor.update(
        signature['ciphertext']
    ) + decryptor.finalize()

    # Check the digest of the file as it exists against the provided signature.
    if digest == signature:
        return {
            'status': 'valid',
            'sig_b': base64.b64encode(digest),
            'sig_a': base64.b64encode(signature)
        }
    else:
        return {
            'status': 'invalid',
            'sig_b': base64.b64encode(digest),
            'sig_a': base64.b64encode(signature)
        }
