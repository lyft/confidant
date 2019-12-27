import unittest
import mock
from datetime import datetime

from confidant.models.credential import Credential


class CredentialTest(unittest.TestCase):

    @mock.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    def test_equals(self, decrypted_pairs_mock):
        decrypted_pairs_mock.return_value = {'test': 'me'}
        cred1 = Credential(
            name='test',
            enabled=True,
            documentation='',
            metadata={},
        )
        cred2 = Credential(
            name='test',
            enabled=True,
            documentation='',
            metadata={},
        )
        self.assertTrue(cred1.equals(cred2))

    @mock.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    def test_not_equals(self, decrypted_pairs_mock):
        decrypted_pairs_mock.return_value = {'test': 'me'}
        cred1 = Credential(
            name='test',
            enabled=True,
            documentation='',
            metadata={},
        )
        cred2 = Credential(
            name='test2',
            enabled=True,
            documentation='',
            metadata={},
        )
        self.assertFalse(cred1.equals(cred2))

    @mock.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs',
        {},
    )
    def test_diff(self):
        modified_by = 'test@example.com'
        modified_date_old = datetime.now
        modified_date_new = datetime.now
        old = Credential(
            name='test',
            revision=1,
            enabled=True,
            documentation='old',
            metadata={'hello': 'world'},
            modified_by=modified_by,
            modified_date=modified_date_old,
        )
        new = Credential(
            name='test2',
            revision=2,
            enabled=True,
            documentation='',
            metadata={'foo': 'bar'},
            modified_by=modified_by,
            modified_date=modified_date_new,
        )
        # TODO: figure out how to test decrypted_credential_pairs. Mocking
        # it is turning out to be difficult.
        expectedDiff = {
            'name': {
                'removed': 'test',
                'added': 'test2',
            },
            'metadata': {
                'removed': ['hello'],
                'added': ['foo'],
            },
            'documentation': {
                'removed': 'old',
                'added': '',
            },
            'modified_by': {
                'removed': modified_by,
                'added': modified_by,
            },
            'modified_date': {
                'removed': modified_date_old,
                'added': modified_date_new,
            },
        }
        self.assertEquals(old.diff(new), expectedDiff)
