from __future__ import absolute_import

from confidant.services import credentialmanager
from pynamodb.exceptions import DoesNotExist


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
