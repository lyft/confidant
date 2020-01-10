from __future__ import absolute_import

from confidant.services import servicemanager

from pynamodb.exceptions import DoesNotExist


def test_get_latest_service_revision(mocker):
    get = mocker.patch(
        'confidant.models.service.Service.get'
    )
    get.side_effect = DoesNotExist()
    res = servicemanager.get_latest_service_revision('123', 1)
    assert res == 2
