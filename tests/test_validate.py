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
        result = verify(file_stream='foobar', sigs_b=signature)
        mock_kms.decrypt.assert_called_once_with(
            CiphertextBlob=test_kms_data['CiphertextBlob'],
            EncryptionContext={}
        )

        print(result)

        expected_result = {
            'status': 'valid',
            'sigs_a': {
                'sha256': '534e6354ad84c29dbcea1dcab2be827361963104fef5d1b73f1b7459be551283d61b34cf7dc356c4615be4b1daf73c83b38aea50373b920cdb5cf2ab4570a099',
                'blake2': 'db5ac5b6afff256d8c0cc123fb00aa35e4cf41ebfcba0444eb027e1cec2a3741c25e3176743801b0a46af5a0515eddf7a7255928a3b45d461ffd951471578bdf'
            },
            'sigs_b': {
                'sha256': '534e6354ad84c29dbcea1dcab2be827361963104fef5d1b73f1b7459be551283d61b34cf7dc356c4615be4b1daf73c83b38aea50373b920cdb5cf2ab4570a099',
                'blake2': 'db5ac5b6afff256d8c0cc123fb00aa35e4cf41ebfcba0444eb027e1cec2a3741c25e3176743801b0a46af5a0515eddf7a7255928a3b45d461ffd951471578bdf'
            }
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
        result = verify(file_stream='foobar-bad', sigs_b=signature)
        print(result)
        mock_kms.decrypt.assert_called_once_with(
            CiphertextBlob=test_kms_data['CiphertextBlob'],
            EncryptionContext={}
        )

        print(result)

        expected_result = {
            'status': 'invalid',
            'sigs_a': {
                'sha256': 'e553f4a34e53c0f1222175422a068b8d1c89ebe00d253cdcb64d635f9bc459018e7f0a77ceb59e586fd70c35e326b797f985bb4dd9eba33f0f8a8a618534907d',
                'blake2': 'd9feff30bc81c0bf96d787a804ba59ab4ad360f0c5b99ce7ed4b6eaf9884ea846aac54683eb1a76b56648e43ec1c20468dcb2028ce0ab2fa116af930e1b1ce7c'
            },
            'sigs_b': {
                'sha256': '534e6354ad84c29dbcea1dcab2be827361963104fef5d1b73f1b7459be551283d61b34cf7dc356c4615be4b1daf73c83b38aea50373b920cdb5cf2ab4570a099',
                'blake2': 'db5ac5b6afff256d8c0cc123fb00aa35e4cf41ebfcba0444eb027e1cec2a3741c25e3176743801b0a46af5a0515eddf7a7255928a3b45d461ffd951471578bdf'
            }
       }

        self.assertEqual(expected_result, result)