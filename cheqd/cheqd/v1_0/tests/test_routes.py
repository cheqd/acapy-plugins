import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ..routes import create_cheqd_did


@pytest.mark.asyncio
async def test_create_cheqd_did_success():
    """Test successful creation of a Cheqd DID."""
    # Arrange
    mock_request = MagicMock()
    mock_request.context = MagicMock()
    mock_request.headers = {
        "Authorization": "Bearer valid_token",  # Replace with a valid token string if needed
        "x-api-key": "valid_api_key",
    }
    mock_request.method = "GET"
    mock_request.path = "/allowed-route"

    # Configure mock context and profile settings
    mock_request["context"].profile = MagicMock()
    mock_request["context"].profile.settings = {  # Explicitly set as a real dictionary
        "admin.admin_api_key": "valid_api_key",
        "admin.admin_insecure_mode": "False",
        "multitenant.enabled": "True",
        "multitenant.base_wallet_routes": "/allowed-route",
    }

    mock_request.json.return_value = {
        "options": {
            "network": "testnet",
            "key_type": "ed25519",
        }
    }

    mock_manager = AsyncMock()
    mock_manager.create.return_value = {
        "did": "did:example:123",
        "verkey": "BnSWTUQmdYCewSGFrRUhT6LmKdcCcSzRGqWXMPnEP168",
    }

    with patch("cheqd.cheqd.v1_0.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        response = await create_cheqd_did(mock_request)

    # Assert

    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json["did"] == "did:example:123"
    assert response_json["verkey"] == "BnSWTUQmdYCewSGFrRUhT6LmKdcCcSzRGqWXMPnEP168"
    mock_manager.create.assert_called_once()
