from datetime import datetime, timedelta
import pytest

from confidant.models.credential import Credential, CredentialArchive
from confidant.scripts.restore import RestoreCredentials


@pytest.fixture
def now():
    return datetime.now()


@pytest.fixture
def old_date():
    return datetime.now() - timedelta(30)


@pytest.fixture()
def save_mock(mocker):
    return mocker.patch('confidant.scripts.restore.RestoreCredentials.save')


@pytest.fixture()
def restore_mock(mocker):
    return mocker.patch('confidant.scripts.restore.RestoreCredentials.restore')


@pytest.fixture
def credentials(mocker, now):
    gmd_mock = mocker.Mock(return_value='test')
    gmd_mock.range_keyname = 'test'
    mocker.patch(
        'confidant.scripts.restore.Credential._get_meta_data',
        return_value=gmd_mock,
    )
    mocker.patch(
        'confidant.scripts.restore.CredentialArchive._get_meta_data',
        return_value=gmd_mock,
    )
    archive_credential = CredentialArchive(
        id='1234',
        name='test',
        data_type='credential',
        revision=2,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    credential = Credential.from_archive_credential(archive_credential)
    archive_revision1 = CredentialArchive(
        id='1234-1',
        name='test revision1',
        data_type='archive-credential',
        revision=1,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    revision1 = Credential.from_archive_credential(archive_revision1)
    archive_revision2 = Credential(
        id='1234-2',
        name='test revision2',
        data_type='archive-credential',
        revision=2,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    revision2 = Credential.from_archive_credential(archive_revision2)

    def from_archive_credential(archive_credential):
        if archive_credential.id == '1234':
            return credential
        elif archive_credential.id == '1234-1':
            return revision1
        elif archive_credential.id == '1234-2':
            return revision2

    mocker.patch.object(
        Credential,
        'from_archive_credential',
        from_archive_credential
    )
    return {
        'credentials': [credential],
        'archive_credentials': [archive_credential],
        'revisions': [revision1, revision2],
        'archive_revisions': [archive_revision1, archive_revision2],
    }


@pytest.fixture
def old_disabled_credentials(credentials, old_date):
    for credential in credentials['credentials']:
        credential.modified_date = old_date
        credential.enabled = False
    for credential in credentials['archive_credentials']:
        credential.modified_date = old_date
        credential.enabled = False
    for revision in credentials['revisions']:
        revision.modified_date = old_date
        revision.enabled = False
    for revision in credentials['archive_revisions']:
        revision.modified_date = old_date
        revision.enabled = False
    return credentials


def test_save(mocker, credentials):
    rc = RestoreCredentials()
    save_mock = mocker.patch('pynamodb.models.BatchWrite.save')
    mocker.patch('pynamodb.models.BatchWrite.commit')
    mocker.patch(
        'confidant.scripts.restore.RestoreCredentials.credential_exists',
        return_value=True,
    )
    rc.save(credentials['credentials'], force=True)
    assert save_mock.called is False

    mocker.patch(
        'confidant.scripts.restore.RestoreCredentials.credential_exists',
        return_value=False,
    )
    rc.save(credentials['credentials'], force=False)
    assert save_mock.called is False

    rc.save(credentials['credentials'], force=True)
    assert save_mock.called is True


def test_restore_credentials(
    mocker,
    old_disabled_credentials,
    save_mock,
):
    mocker.patch(
        'confidant.scripts.restore.CredentialArchive.batch_get',
        return_value=old_disabled_credentials['archive_revisions']
    )
    rc = RestoreCredentials()
    rc.restore(old_disabled_credentials['archive_credentials'], force=True)

    save_mock.assert_called_with(
        old_disabled_credentials['credentials'] + old_disabled_credentials['revisions'],  # noqa:E501
        force=True,
    )


def test_restore_old_disabled_unmapped_credential_no_force(
    mocker,
    old_disabled_credentials,
    save_mock,
):
    mocker.patch(
        'confidant.scripts.restore.CredentialArchive.batch_get',
        return_value=old_disabled_credentials['archive_revisions']
    )
    rc = RestoreCredentials()
    rc.restore(old_disabled_credentials['archive_credentials'], force=False)

    save_mock.assert_called_with(
        old_disabled_credentials['credentials'] + old_disabled_credentials['revisions'],  # noqa:E501
        force=False,
    )


def test_run_no_archive_table(mocker):
    mocker.patch(
        'confidant.scripts.restore.settings.DYNAMODB_TABLE_ARCHIVE',
        None,
    )
    rc = RestoreCredentials()
    assert rc.run(_all=True, force=True, ids=None) == 1


def test_run_bad_args(mocker):
    rc = RestoreCredentials()
    assert rc.run(_all=False, force=True, ids=None) == 1
    assert rc.run(_all=True, force=True, ids='1234') == 1


def test_run_all(
    mocker,
    credentials,
    restore_mock,
):
    mocker.patch(
        'confidant.scripts.restore.CredentialArchive.data_type_date_index.query',  # noqa:E501
        return_value=credentials['archive_credentials']
    )
    rc = RestoreCredentials()
    rc.run(_all=True, force=True, ids=None)
    restore_mock.assert_called_with(
        credentials['archive_credentials'],
        force=True,
    )


def test_run_ids(
    mocker,
    credentials,
    restore_mock,
):
    mocker.patch(
        'confidant.scripts.restore.CredentialArchive.batch_get',
        return_value=credentials['archive_credentials']
    )
    cred_ids = [
        cred.id for
        cred in credentials['archive_credentials']
    ]
    ids = ','.join(cred_ids)
    rc = RestoreCredentials()
    rc.run(_all=False, force=True, ids=ids)

    restore_mock.assert_called_with(
        credentials['archive_credentials'],
        force=True,
    )
