from datetime import datetime, timedelta
import pytest

from confidant.models.service import Service
from confidant.models.credential import Credential, CredentialArchive
from confidant.scripts.archive import ArchiveCredentials


@pytest.fixture
def now():
    return datetime.now()


@pytest.fixture
def old_date():
    return datetime.now() - timedelta(30)


@pytest.fixture
def credentials(mocker, now):
    gmd_mock = mocker.Mock(return_value='test')
    gmd_mock.range_keyname = 'test'
    mocker.patch(
        'confidant.scripts.archive.Credential._get_meta_data',
        return_value=gmd_mock,
    )
    mocker.patch(
        'confidant.scripts.archive.CredentialArchive._get_meta_data',
        return_value=gmd_mock,
    )
    credential = Credential(
        id='1234',
        name='test',
        data_type='credential',
        revision=2,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    credential.delete = mocker.Mock()
    archive_credential = CredentialArchive.from_credential(credential)
    archive_credential.save = mocker.Mock()
    revision1 = Credential(
        id='1234-1',
        name='test revision1',
        data_type='archive-credential',
        revision=1,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    revision1.delete = mocker.Mock()
    archive_revision1 = CredentialArchive.from_credential(revision1)
    archive_revision1.save = mocker.Mock()
    revision2 = Credential(
        id='1234-2',
        name='test revision2',
        data_type='archive-credential',
        revision=2,
        enabled=True,
        modified_date=now,
        modified_by='test@example.com',
    )
    revision2.delete = mocker.Mock()
    archive_revision2 = CredentialArchive.from_credential(revision2)
    archive_revision2.save = mocker.Mock()

    def from_credential(credential):
        if credential.id == '1234':
            return archive_credential
        elif credential.id == '1234-1':
            return archive_revision1
        elif credential.id == '1234-2':
            return archive_revision2

    mocker.patch.object(CredentialArchive, 'from_credential', from_credential)
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


@pytest.fixture
def no_mapped_service(mocker):
    mocker.patch(
        'confidant.scripts.archive.servicemanager.get_services_for_credential',
        return_value=[],
    )


@pytest.fixture
def mapped_service(mocker):
    mocker.patch(
        'confidant.scripts.archive.servicemanager.get_services_for_credential',
        return_value=Service(id='test-service', revision=1, enabled=True),
    )


def test_run_old_disabled_unmapped_credential(
    mocker,
    old_disabled_credentials,
    no_mapped_service,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=old_disabled_credentials['credentials']
    )
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=True)

    for credential in old_disabled_credentials['credentials']:
        assert credential.delete.called is True
    for credential in old_disabled_credentials['archive_credentials']:
        assert credential.save.called is True
    for revision in old_disabled_credentials['revisions']:
        assert revision.delete.called is True
    for revision in old_disabled_credentials['archive_revisions']:
        assert revision.save.called is True


def test_run_old_disabled_unmapped_credential_no_force(
    mocker,
    old_disabled_credentials,
    no_mapped_service,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=old_disabled_credentials['credentials']
    )
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=False)

    for credential in old_disabled_credentials['credentials']:
        assert credential.delete.called is False
    for credential in old_disabled_credentials['archive_credentials']:
        assert credential.save.called is False
    for revision in old_disabled_credentials['revisions']:
        assert revision.delete.called is False
    for revision in old_disabled_credentials['archive_revisions']:
        assert revision.save.called is False


def test_run_old_disabled_mapped_credential(
    mocker,
    old_disabled_credentials,
    mapped_service,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=old_disabled_credentials['credentials']
    )
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=True)

    for credential in old_disabled_credentials['credentials']:
        assert credential.delete.called is False
    for credential in old_disabled_credentials['archive_credentials']:
        assert credential.save.called is False
    for revision in old_disabled_credentials['revisions']:
        assert revision.delete.called is False
    for revision in old_disabled_credentials['archive_revisions']:
        assert revision.save.called is False


def test_run_new_enabled_unmapped_credential(
    mocker,
    credentials,
    no_mapped_service,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=credentials['credentials']
    )
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=credentials['revisions']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=True)

    for credential in credentials['credentials']:
        assert credential.delete.called is False
    for credential in credentials['archive_credentials']:
        assert credential.save.called is False
    for revision in credentials['revisions']:
        assert revision.delete.called is False
    for revision in credentials['archive_revisions']:
        assert revision.save.called is False


def test_run_no_archive_table(mocker):
    mocker.patch(
        'confidant.scripts.archive.settings.DYNAMODB_TABLE_ARCHIVE',
        None,
    )
    ac = ArchiveCredentials()
    assert ac.run(days=10, force=True) == 1
