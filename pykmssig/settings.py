from decouple import config


SIGNING_KEY_ALIAS = config('SIGNING_KEY_ALIAS', default='alias/pykmssig')
