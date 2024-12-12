import json
from unittest.mock import AsyncMock, patch

import pytest
from acapy_agent.wallet.error import WalletError
from aiohttp import web

from ..did.manager import CheqdDIDManagerError
from ..routes import create_cheqd_did


@pytest.mark.asyncio
async def test_create_cheqd_did(mock_request, mock_manager):
    # Arrange
    with patch(
        "cheqd.cheqd.v1_0.routes.CheqdDIDManager", return_value=mock_manager
    ) as mock_constructor:
        # Act
        response = await create_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json["did"] == "did:cheqd:testnet:123"
    assert response_json["verkey"] == "MOCK_VERIFICATION_KEY"
    mock_manager.create.assert_called_with({"network": "testnet", "key_type": "ed25519"})
    mock_constructor.assert_called_once_with(
        mock_request["context"].profile, "MOCK_REGISTRAR_URL", "MOCK_RESOLVER_URL"
    )


@pytest.mark.asyncio
async def test_create_cheqd_did_missing_body(mock_request, mock_manager):
    # Arrange
    mock_request.json = AsyncMock(side_effect=Exception("Invalid JSON"))
    with patch("cheqd.cheqd.v1_0.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        response = await create_cheqd_did(mock_request)

    # Assert
    assert response.status == 200
    response_json = json.loads(response.text)
    assert response_json["did"] == "did:cheqd:testnet:123"
    assert response_json["verkey"] == "MOCK_VERIFICATION_KEY"
    mock_manager.create.assert_called_with(None)


@pytest.mark.asyncio
async def test_create_cheqd_did_manager_error(mock_request, mock_manager):
    # Arrange
    mock_manager.create.side_effect = CheqdDIDManagerError("Manager error")
    with patch("cheqd.cheqd.v1_0.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPInternalServerError) as e:
            await create_cheqd_did(mock_request)

        # Assert
        assert "Manager error" in str(e.value)
        assert isinstance(e.value, web.HTTPInternalServerError)


@pytest.mark.asyncio
async def test_create_cheqd_did_wallet_error(mock_request, mock_manager):
    # Arrange
    mock_manager.create.side_effect = WalletError("Wallet error")
    with patch("cheqd.cheqd.v1_0.routes.CheqdDIDManager", return_value=mock_manager):
        # Act
        with pytest.raises(web.HTTPBadRequest) as e:
            await create_cheqd_did(mock_request)

        # Assert
        assert "Wallet error" in str(e.value)
        assert isinstance(e.value, web.HTTPBadRequest)
