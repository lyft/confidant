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
