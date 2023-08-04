from datetime import datetime, timedelta
import pytest
from pytest_mock.plugin import MockerFixture
from typing import Dict, List
from unittest.mock import MagicMock

from confidant.models.service import Service
from confidant.models.credential import Credential, CredentialArchive
from confidant.scripts.archive import ArchiveCredentials
from confidant.services import credentialmanager


@pytest.fixture
def now() -> datetime:
    return datetime.now()


@pytest.fixture
def old_date() -> datetime:
    return datetime.now() - timedelta(30)


@pytest.fixture()
def save_mock(mocker: MockerFixture) -> MagicMock:
    return mocker.patch('confidant.scripts.archive.credentialmanager.'
                        '_save_credentials_to_archive')


@pytest.fixture()
def delete_mock(mocker: MockerFixture) -> MagicMock:
    return mocker.patch('confidant.scripts.archive.credentialmanager.'
                        '_delete_credentials')


@pytest.fixture()
def archive_mock(mocker: MockerFixture) -> MagicMock:
    return mocker.patch('confidant.scripts.archive.credentialmanager.'
                        'archive_credentials')


@pytest.fixture
def credentials(
    mocker: MockerFixture,
    now: datetime
) -> Dict[str, List[Credential]]:
    gmd_mock = mocker.Mock(return_value='test')
    gmd_mock.range_keyname = 'test'
    mocker.patch(
        'confidant.services.credentialmanager.Credential._get_meta_data',
        return_value=gmd_mock,
    )
    mocker.patch(
        'confidant.services.credentialmanager.CredentialArchive.'
        '_get_meta_data',
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

    def from_credential(credential: Credential):
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
def old_disabled_credentials(
    credentials: Dict[str, List[Credential]],
    old_date: datetime
) -> Dict[str, List[Credential]]:
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
def no_mapped_service(mocker: MockerFixture):
    mocked = mocker.patch.object(Service, 'data_type_date_index')
    mocked.query = mocker.Mock(return_value=[])
    mocker.patch(
        'confidant.scripts.archive.credentialmanager._credential_in_service',
        return_value=False,
    )


@pytest.fixture
def mapped_service(mocker: MockerFixture):
    mocked = mocker.patch.object(Service, 'data_type_date_index')
    mocked.query = mocker.Mock(
        return_value=[Service(id='test-service', revision=1, enabled=True)],
    )
    mocker.patch(
        'confidant.scripts.archive.credentialmanager._credential_in_service',
        return_value=True,
    )


def test_save_credentials_to_archive(
    mocker: MockerFixture,
    credentials: Dict[str, List[Credential]]
):
    mocker.patch('pynamodb.models.BatchWrite.commit')
    save_mock = mocker.patch('pynamodb.models.BatchWrite.save')
    credentialmanager._save_credentials_to_archive(credentials['credentials'],
                                                   force=False)
    assert save_mock.called is False

    credentialmanager._save_credentials_to_archive(credentials['credentials'],
                                                   force=True)
    assert save_mock.called is True


def test_delete(
    mocker: MockerFixture,
    credentials: Dict[str, List[Credential]]
):
    mocker.patch('pynamodb.models.BatchWrite.commit')
    delete_mock = mocker.patch('pynamodb.models.BatchWrite.delete')
    credentialmanager._delete_credentials(credentials['credentials'],
                                          force=False)
    assert delete_mock.called is False

    credentialmanager._delete_credentials(credentials['credentials'],
                                          force=True)
    assert delete_mock.called is True


def test_archive_old_disabled_unmapped_credential(
    mocker: MockerFixture,
    old_disabled_credentials: Dict[str, List[Credential]],
    no_mapped_service: None,
    save_mock: MagicMock,
    delete_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=old_disabled_credentials['credentials']
    )
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    credentialmanager.archive_credentials(
        old_disabled_credentials['credentials'],
        force=True,
    )

    save_mock.assert_called_with(
        old_disabled_credentials['archive_credentials'] + old_disabled_credentials['archive_revisions'],  # noqa:E501
        force=True,
    )
    delete_mock.assert_called_with(
        old_disabled_credentials['revisions'] + old_disabled_credentials['credentials'],  # noqa:E501
        force=True,
    )


def test_archive_old_disabled_unmapped_credential_no_force(
    mocker: MockerFixture,
    old_disabled_credentials: Dict[str, List[Credential]],
    no_mapped_service: None,
    save_mock: MagicMock,
    delete_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    credentialmanager.archive_credentials(
        old_disabled_credentials['credentials'],
        force=False,
    )

    save_mock.assert_called_with(
        old_disabled_credentials['archive_credentials'] + old_disabled_credentials['archive_revisions'],  # noqa:E501
        force=False,
    )
    delete_mock.assert_called_with(
        old_disabled_credentials['revisions'] + old_disabled_credentials['credentials'],  # noqa:E501
        force=False,
    )


def test_archive_old_disabled_mapped_credential(
    mocker: MockerFixture,
    old_disabled_credentials: Dict[str, List[Credential]],
    mapped_service: None,
    save_mock: MagicMock,
    delete_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['revisions']
    )
    credentialmanager.archive_credentials(
        old_disabled_credentials['credentials'],
        force=True,
    )

    assert save_mock.called is False
    assert delete_mock.called is False


def test_run_no_archive_table(mocker: MockerFixture):
    mocker.patch(
        'confidant.scripts.archive.settings.DYNAMODB_TABLE_ARCHIVE',
        None,
    )
    ac = ArchiveCredentials()
    assert ac.run(days=10, force=True, ids=None) == 1


def test_run_bad_args(mocker: MockerFixture):
    ac = ArchiveCredentials()
    assert ac.run(days=None, force=True, ids=None) == 1
    assert ac.run(days=10, force=True, ids='1234') == 1


def test_run_days_new_enabled_credential(
    mocker: MockerFixture,
    credentials: Dict[str, List[Credential]],
    archive_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=credentials['credentials']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=True, ids=None)
    archive_mock.assert_called_with(
        [],
        force=True,
    )


def test_run_days_old_disabled_credentials(
    mocker: MockerFixture,
    old_disabled_credentials: Dict[str, List[Credential]],
    archive_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.data_type_date_index.query',
        return_value=old_disabled_credentials['credentials']
    )
    ac = ArchiveCredentials()
    ac.run(days=10, force=True, ids=None)

    archive_mock.assert_called_with(
        old_disabled_credentials['credentials'],
        force=True,
    )


def test_run_ids_new_enabled_credentials(
    mocker: MockerFixture,
    credentials: Dict[str, List[Credential]],
    archive_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=credentials['credentials']
    )
    cred_ids = [
        cred.id for
        cred in credentials['credentials']
    ]
    ids = ','.join(cred_ids)
    ac = ArchiveCredentials()
    ac.run(days=None, force=True, ids=ids)

    archive_mock.assert_called_with(
        [],
        force=True,
    )


def test_run_ids_old_disabled_credentials(
    mocker: MockerFixture,
    old_disabled_credentials: Dict[str, List[Credential]],
    archive_mock: MagicMock,
):
    mocker.patch(
        'confidant.scripts.archive.Credential.batch_get',
        return_value=old_disabled_credentials['credentials']
    )
    cred_ids = [
        cred.id for
        cred in old_disabled_credentials['credentials']
    ]
    ids = ','.join(cred_ids)
    ac = ArchiveCredentials()
    ac.run(days=None, force=True, ids=ids)

    archive_mock.assert_called_with(
        old_disabled_credentials['credentials'],
        force=True,
    )
