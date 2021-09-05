import pytest


@pytest.mark.sync
def test_client_production_endpoint(client):
    assert "https://backbone.dev/" in client._base_url
