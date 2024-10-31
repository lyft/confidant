from lyft_lumos_common.services.panther import PantherClient

from confidant.settings import PANTHER_BASE_URL
from confidant.settings import PANTHER_BEARER_TOKEN


def get_panther_client() -> PantherClient:
    return PantherClient(
        bearer_token=PANTHER_BEARER_TOKEN,
        base_url=PANTHER_BASE_URL)


panther_client = get_panther_client()
