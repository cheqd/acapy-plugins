from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_request():
    mock_request = MagicMock()
    mock_request.context = MagicMock()

    mock_request.headers = {
        "Authorization": "Bearer valid_token",
        "x-api-key": "valid_api_key",
    }
    mock_request.method = "GET"
    mock_request.path = "/allowed-route"

    mock_request["context"].settings = {
        "plugin_config": {
            "registrar_url": "MOCK_REGISTRAR_URL",
            "resolver_url": "MOCK_RESOLVER_URL",
        },
    }

    mock_request["context"].profile = MagicMock()
    mock_request["context"].profile.settings = {
        "admin.admin_api_key": "valid_api_key",
        "admin.admin_insecure_mode": "False",
        "multitenant.enabled": "True",
        "multitenant.base_wallet_routes": "/allowed-route",
    }

    mock_request.json = AsyncMock(
        return_value={
            "options": {
                "network": "testnet",
                "key_type": "ed25519",
            }
        }
    )

    return mock_request


@pytest.fixture
def mock_manager():
    mock_manager = AsyncMock()
    mock_manager.create.return_value = {
        "did": "did:cheqd:testnet:123",
        "verkey": "MOCK_VERIFICATION_KEY",
    }

    return mock_manager
