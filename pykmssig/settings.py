from decouple import config

KMS_SIGNING_KEY = config('KMS_SIGNING_KEY')

VALIDATION_CIPHERS = config('VALIDATION_CIPHERS', 'sha512')
