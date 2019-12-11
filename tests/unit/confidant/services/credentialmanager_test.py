from __future__ import absolute_import
import unittest

from mock import patch
from confidant.services import credentialmanager
from pynamodb.exceptions import DoesNotExist


class CredentialManagerTest(unittest.TestCase):

    @patch('confidant.models.blind_credential.BlindCredential.get')
    def test_get_latest_blind_credential_revision(self, get):
        get.side_effect = DoesNotExist()
        res = credentialmanager.get_latest_blind_credential_revision('123', 1)
        assert res == 2

    @patch('confidant.models.credential.Credential.get')
    def test_get_latest_credential_revision(self, get):
        get.side_effect = DoesNotExist()
        res = credentialmanager.get_latest_credential_revision('123', 1)
        assert res == 2

    def test_lowercase_credential_pairs(self):
        test = {
            'A': '123',
            'B': '345',
            'C': '678'
        }

        expected = {
            'a': '123',
            'b': '345',
            'c': '678'
        }
        res = credentialmanager.lowercase_credential_pairs(test)
        assert res == expected
