import boto3
import unittest
import json

from moto import mock_kms
from moto import mock_sts

class CryptoTest(unittest.TestCase):
    @mock_kms
    @mock_sts
    def test_sign_verify(self):
        from pykmssig import crypto

        sts_client = boto3.client('sts', region_name='us-west-2')
        boto_session = boto3.session.Session()

        c = crypto.Operation(boto_session=boto_session)

        c.sts_client = sts_client

        s_ciphertext = c.sign(json.dumps({'foo': 'bar'}))

        verify_status = c.verify(
            s_ciphertext,
            plaintext=json.dumps({'foo': 'bar'})
        )

        assert verify_status['status'] == 'valid'
