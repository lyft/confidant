from datetime import datetime

from confidant.models.credential import Credential


def test_equals(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
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
    assert cred1.equals(cred2) is True


def test_not_equals(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
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
    assert cred1.equals(cred2) is False


def test_not_equals_different_rotation_frequency(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    decrypted_pairs_mock.return_value = {'test': 'me'}
    cred1 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        rotation_frequency_s=2,
    )
    cred2 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        rotation_frequency_s=3,
    )
    assert cred1.equals(cred2) is False


def test_not_equals_different_sox_category(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    decrypted_pairs_mock.return_value = {'test': 'me'}
    cred1 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        sox_category='ADMIN_PRIV',
    )
    cred2 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        sox_category='FINANCIALLY_SENSITIVE',
    )
    assert cred1.equals(cred2) is False


def test_diff(mocker):
    mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs',
        {}
    )
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
        sox_category='FINANCIALLY_SENSITIVE',
        rotation_frequency_s=2,
        next_rotation_date=modified_date_old(),
    )
    new = Credential(
        name='test2',
        revision=2,
        enabled=True,
        documentation='',
        metadata={'foo': 'bar'},
        modified_by=modified_by,
        modified_date=modified_date_new,
        sox_category='ADMIN_PRIV',
        rotation_frequency_s=3,
        next_rotation_date=modified_date_new(),
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
        'sox_category': {
            'removed': 'FINANCIALLY_SENSITIVE',
            'added': 'ADMIN_PRIV',
        },
        'rotation_frequency_s': {
            'removed': 2,
            'added': 3,
        },
        'next_rotation_date': {
            'removed': old.next_rotation_date,
            'added': new.next_rotation_date,
        },
        # No diff for last rotation date as both credentials have the same
    }
    assert old.diff(new) == expectedDiff
