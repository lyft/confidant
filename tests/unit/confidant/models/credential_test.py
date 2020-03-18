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
        tags=['ADMIN_PRIV'],
    )
    cred2 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        tags=['ADMIN_PRIV'],
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


def test_not_equals_different_tags(mocker):
    decrypted_pairs_mock = mocker.patch(
        'confidant.models.credential.Credential.decrypted_credential_pairs'
    )
    decrypted_pairs_mock.return_value = {'test': 'me'}
    cred1 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        tags=['ADMIN_PRIV'],
    )
    cred2 = Credential(
        name='test',
        enabled=True,
        documentation='',
        metadata={},
        tags=['FINANCIALLY_SENSITIVE'],
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
        tags=['FINANCIALLY_SENSITIVE', 'IMPORTANT'],
    )
    new = Credential(
        name='test2',
        revision=2,
        enabled=True,
        documentation='',
        metadata={'foo': 'bar'},
        modified_by=modified_by,
        modified_date=modified_date_new,
        tags=['ADMIN_PRIV', 'IMPORTANT'],
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
        'tags': {
            'removed': ['FINANCIALLY_SENSITIVE'],
            'added': ['ADMIN_PRIV'],
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

    
def test_next_rotation_date_no_rotation_required(mocker):
    mocker.patch(
        'confidant.models.credential.settings.TAGS_EXCLUDING_ROTATION',
        ['ADMIN_PRIV'],
    )
    assert Credential(tags=['ADMIN_PRIV']).next_rotation_date is None


def test_next_rotation_date_never_rotated(mocker):
    mocker.patch(
        'confidant.models.credential.settings.TAGS_EXCLUDING_ROTATION',
        [],
    )
    cred = Credential(tags=['FINANCIALLY_SENSITIVE'])
    assert cred.next_rotation_date <= datetime.utcnow()


def test_next_rotation_date_last_rotation_present(mocker):
    mocker.patch(
        'confidant.models.credential.settings.TAGS_EXCLUDING_ROTATION',
        [],
    )
    mocker.patch(
        'confidant.models.credential.settings.MAXIMUM_ROTATION_DAYS',
        100,
    )
    mocker.patch(
        'confidant.models.credential.settings.ROTATION_DAYS_CONFIG',
        {'FINANCIALLY_SENSITIVE': 30},
    )
    cred = Credential(
        tags=['FINANCIALLY_SENSITIVE'],
        last_rotation_date=datetime(2020, 1, 1),
    )
    assert cred.next_rotation_date == datetime(2020, 1, 31)


def test_exempt_from_rotation(mocker):
    mocker.patch(
        'confidant.models.credential.settings.TAGS_EXCLUDING_ROTATION',
        ['ADMIN_PRIV'],
    )
    cred = Credential(tags=['ADMIN_PRIV'])
    assert cred.exempt_from_rotation is True

    cred = Credential(tags=['FINANCIALLY_SENSITIVE'])
    assert cred.exempt_from_rotation is False
