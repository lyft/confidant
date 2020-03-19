from __future__ import absolute_import

from confidant.models.credential import Credential
from confidant.services import credentialmanager
from pynamodb.exceptions import DoesNotExist


def test_get_revision_ids_for_credential():
    credential = Credential(
        id='1234',
        revision=3,
        name='test',
        enabled=True,
    )
    assert credentialmanager.get_revision_ids_for_credential(credential) == [
        '1234-1',
        '1234-2',
        '1234-3',
    ]


def test_get_latest_blind_credential_revision(mocker):
    get = mocker.patch(
        'confidant.models.blind_credential.BlindCredential.get'
    )
    get.side_effect = DoesNotExist()
    res = credentialmanager.get_latest_blind_credential_revision('123', 1)
    assert res == 2


def test_get_latest_credential_revision(mocker):
    get = mocker.patch(
        'confidant.models.credential.Credential.get'
    )
    get.side_effect = DoesNotExist()
    res = credentialmanager.get_latest_credential_revision('123', 1)
    assert res == 2


def test_check_credential_pair_values(mocker):
    cred_pairs_success = {
        'A': '1'
    }
    cred_pairs_fail = {
        'A': ['1', '2', '3']
    }
    cred_pair_fail_2 = {
        'A': {'1': '2'}
    }
    result = credentialmanager.check_credential_pair_values(cred_pairs_fail)
    assert result[0] is False
    result = credentialmanager.check_credential_pair_values(cred_pair_fail_2)
    assert result[0] is False
    result = credentialmanager.check_credential_pair_values(cred_pairs_success)
    assert result[0] is True


def test_lowercase_credential_pairs():
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
