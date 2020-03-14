from datetime import datetime

from confidant.models.credential import Credential, CredentialArchive


def test_equals(mocker):
    mocker.patch(
        'confidant.models.credential.Credential'
        '._get_decrypted_credential_pairs',
        return_value={'test': 'me'},
    )
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
    mocker.patch(
        'confidant.models.credential.Credential'
        '._get_decrypted_credential_pairs',
        return_value={'test': 'me'},
    )
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


def test_diff(mocker):
    mocker.patch(
        'confidant.models.credential.Credential'
        '._get_decrypted_credential_pairs',
        return_value={},
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
    assert old.diff(new) == expectedDiff


def test_credential_archive(mocker):
    mocker.patch(
        'confidant.models.credential.Credential'
        '._get_decrypted_credential_pairs',
        return_value={},
    )
    cred = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
    )
    archive_cred = CredentialArchive.from_credential(cred)
    # TODO: do a more thorough equality test here.
    assert cred.id == archive_cred.id
