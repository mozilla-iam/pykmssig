# pykmssig
A python library inspired by https://github.com/codahale/kmssig

# Build Status

[![Build Status](https://travis-ci.org/mozilla-iam/pykmssig.svg?branch=master)](https://travis-ci.org/mozilla-iam/pykmssig)

# Why pykmssig?

Sometimes you need to validate a message passing multiple AWS accounts and
services has not been tampered with in transit.

Let's say we have three AWS accounts Account A, Account B, and Account C.

Account A wants to publish messages to a Kinesis stream in Account B.
Account B runs the Kinesis stream and some light data validation but does not
modify the data.

Account C is a high security account and only allows Account B put access to a single
dynamo table.  In the event account B is compromised how does account C guarantee
the integrity of the messages in transit?

__Answer__ : pykmssig

pykmssig allows the owners of Account A to sign and encrypt a signature against a KMS
key let's call it _kms-key-alpha_ in order to do this kms-key-alpha needs to allow Account
owner A the ability to encrypt messages.  This encrypts the signature data.  A second key
_kms-key-beta_ can be used to provide data at rest protection.  Account A, B, and C can all
be allowed decrypt for _kms-key-beta_ but only Account C should be allowed to decrypt using
_kms-key-alpha_ to verify the message was not tampered with in transit.


# Installing

```
git clone https://github.com/andrewkrug/pykmssig
pip install -r requirements.txt
python setup.py install
```

# Setting up your environment

This looks for the environment variable SIGNING_KEY_ALIAS this should be a precreated
alias for the KMS key you'd like to use to sign.  If you've used the provided cloudformation
stack template you need not change this.

# Usage

``` python

# Signing a payload
from pykmssig import crypto

o = crypto.Operation()

result = o.sign(plaintext={'foo': 'bar'})

# The result of this operation will be ciphertext.

```

Verifying the payload:

``` python

# Verification

from pykmssig import crypto

o = crypto.Operation()

result = o.verify(
    ciphertext=ciphertext,
    plaintext={'foo': 'bar'}
)

"""Result returns a dictionary that looks as follows.""""
{
    'status': 'valid',
    'sig_b': b'U05jVK2Ewp286h3Ksr6Cc2GWMQT+9dG3Pxt0Wb5VEoPWGzTPfcNWxGFb5LHa9zyDs4rqUDc7kgzbXPKrRXCgmQ==',
    'sig_a': b'U05jVK2Ewp286h3Ksr6Cc2GWMQT+9dG3Pxt0Wb5VEoPWGzTPfcNWxGFb5LHa9zyDs4rqUDc7kgzbXPKrRXCgmQ=='
}

```
