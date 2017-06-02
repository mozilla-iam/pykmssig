import base64
import json
import unittest
import os

from unittest.mock import patch


class ValidationTest(unittest.TestCase):

    def setUp(self):
        fixtures = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'data/fixtures.json')
        with open(fixtures) as artifacts:
            self.test_artifacts = json.load(artifacts)
        os.environ['KMS_SIGNING_KEY'] = self.test_artifacts['dummy_kms_arn']

    @patch('pykmssig.validate.kms')
    def test_verify(self, mock_kms):
        test_kms_data = {
            'Plaintext': base64.b64decode(self.test_artifacts['Plaintext']),
            'CiphertextBlob': base64.b64decode(self.test_artifacts['CiphertextBlob'])
        }

        test_iv = base64.b64decode(self.test_artifacts['IV'])

        mock_kms.decrypt.return_value = test_kms_data

        signature = {
            'ciphertext': base64.b64decode(self.test_artifacts['expected_ciphertext']),
            'ciphertext_key': test_kms_data['CiphertextBlob'],
            'iv': test_iv,
            'tag': base64.b64decode(self.test_artifacts['expected_tag'])
        }

        from pykmssig.validate import verify
        result = verify(file_stream='foobar', signature=signature)
        mock_kms.decrypt.assert_called_once_with(
            CiphertextBlob=test_kms_data['CiphertextBlob'],
            EncryptionContext={}
        )

        expected_result = {
            'status': 'valid',
            'sig_b': b'U05jVK2Ewp286h3Ksr6Cc2GWMQT+9dG3Pxt0Wb5VEoPWGzTPfcNWxGFb5LHa9zyDs4rqUDc7kgzbXPKrRXCgmQ==',
            'sig_a': b'U05jVK2Ewp286h3Ksr6Cc2GWMQT+9dG3Pxt0Wb5VEoPWGzTPfcNWxGFb5LHa9zyDs4rqUDc7kgzbXPKrRXCgmQ=='
        }

        self.assertEqual(expected_result, result)

    @patch('pykmssig.validate.kms')
    def test_verify_fail(self, mock_kms):
        test_kms_data = {
            'Plaintext': base64.b64decode(self.test_artifacts['Plaintext']),
            'CiphertextBlob': base64.b64decode(self.test_artifacts['CiphertextBlob'])
        }

        test_iv = base64.b64decode(self.test_artifacts['IV'])

        mock_kms.decrypt.return_value = test_kms_data

        signature = {
            'ciphertext': base64.b64decode(self.test_artifacts['expected_ciphertext']),
            'ciphertext_key': test_kms_data['CiphertextBlob'],
            'iv': test_iv,
            'tag': base64.b64decode(self.test_artifacts['expected_tag'])
        }

        from pykmssig.validate import verify
        result = verify(file_stream='foobar-bad', signature=signature)

        mock_kms.decrypt.assert_called_once_with(
            CiphertextBlob=test_kms_data['CiphertextBlob'],
            EncryptionContext={}
        )

        expected_result = {
            'status': 'invalid',
            'sig_b': b'5VP0o05TwPEiIXVCKgaLjRyJ6+ANJTzctk1jX5vEWQGOfwp3zrWeWG/XDDXjJreX+YW7Tdnroz8PiophhTSQfQ==',
            'sig_a': b'U05jVK2Ewp286h3Ksr6Cc2GWMQT+9dG3Pxt0Wb5VEoPWGzTPfcNWxGFb5LHa9zyDs4rqUDc7kgzbXPKrRXCgmQ=='
        }

        self.assertEqual(expected_result, result)
