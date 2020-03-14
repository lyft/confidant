from datetime import datetime
from unittest import mock

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


def test_not_equals_different_category(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    decrypted_pairs_mock.return_value = {'test': 'me'}
    cred1 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        category='ADMIN_PRIV',
    )
    cred2 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        category='FINANCIALLY_SENSITIVE',
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
        category='FINANCIALLY_SENSITIVE',
    )
    new = Credential(
        name='test2',
        revision=2,
        enabled=True,
        documentation='',
        metadata={'foo': 'bar'},
        modified_by=modified_by,
        modified_date=modified_date_new,
        category='ADMIN_PRIV',
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
        'category': {
            'removed': 'FINANCIALLY_SENSITIVE',
            'added': 'ADMIN_PRIV',
        },
    }
    assert old.diff(new) == expectedDiff


def test_next_rotation_date_no_rotation_required():
    assert Credential(category='ADMIN_PRIV').next_rotation_date is None


def test_next_rotation_date_last_rotation_present(mocker):
    mocker.patch.object(
        Credential,
        'rotation_frequency',
        new_callable=mock.PropertyMock,
        return_value=30
    )
    cred = Credential(
        category='FINANCIALLY_SENSITIVE',
        last_rotation_date=datetime(2020, 1, 1),
    )
    assert cred.next_rotation_date == datetime(2020, 1, 31)


def test_requires_rotation():
    cred = Credential(category='FINANCIALLY_SENSITIVE')
    assert cred.requires_rotation is True

    cred = Credential(category='ADMIN_PRIV')
    assert cred.requires_rotation is False
