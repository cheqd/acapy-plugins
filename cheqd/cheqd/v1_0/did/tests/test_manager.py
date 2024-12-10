from unittest.mock import ANY, call, patch

import pytest
from acapy_agent.resolver.base import DIDNotFound
from acapy_agent.wallet.error import WalletError

from ...did.base import CheqdDIDManagerError
from ..manager import CheqdDIDManager
from .mocks import (
    registrar_create_responses,
    registrar_generate_did_doc_response,
    registrar_responses_network_fail,
    registrar_responses_no_signing_request,
    registrar_update_responses,
    setup_mock_registrar,
    setup_mock_resolver,
)


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create(mock_registrar_instance, profile):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
    )
    manager = CheqdDIDManager(profile)

    # Act
    response = await manager.create()

    # Assert
    assert response["did"] == "did:cheqd:testnet:123456"
    assert response["verkey"] is not None
    assert response["didDocument"]["MOCK_KEY"] == "MOCK_VALUE"

    mock_registrar_instance.return_value.create.assert_has_calls(
        [
            call(
                {
                    "didDocument": {
                        "id": "did:cheqd:testnet:123456",
                        "verificationMethod": {"publicKey": "someVerificationKey"},
                    },
                    "network": "testnet",
                }
            ),
            call(
                {
                    "jobId": "MOCK_ID",
                    "network": "testnet",
                    "secret": {
                        "signingResponse": [
                            {
                                "kid": "MOCK_KID",
                                "signature": ANY,
                            }
                        ]
                    },
                }
            ),
        ]
    )


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_with_insecure_seed(mock_registrar_instance, profile):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
    )
    profile.settings["wallet.allow_insecure_seed"] = False
    manager = CheqdDIDManager(profile)

    # Act
    options = {"seed": "insecure-seed"}
    with pytest.raises(Exception) as e:
        await manager.create(options=options)

    # Assert
    assert isinstance(e.value, WalletError)
    assert str(e.value) == "Insecure seed is not allowed"


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_with_invalid_did_document(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        None,
        registrar_create_responses,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "Error constructing DID Document"


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_with_signing_failure(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_responses_no_signing_request,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "No signing requests available for create."


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_create_with_registration_failure(
    mock_registrar_instance,
    profile,
):
    # Arrange
    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_responses_network_fail,
    )
    manager = CheqdDIDManager(profile)

    # Act
    with pytest.raises(Exception) as e:
        await manager.create()

    # Assert
    assert isinstance(e.value, CheqdDIDManagerError)
    assert str(e.value) == "Error registering DID Network failure"


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDResolver")
@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_update(mock_registrar_instance, mock_resolver_instance, profile):
    # Arrange
    did = "did:cheqd:testnet:123456"
    did_doc = {"MOCK_KEY": "MOCK_VALUE"}

    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
        registrar_update_responses,
    )
    setup_mock_resolver(mock_resolver_instance.return_value)

    manager = CheqdDIDManager(profile)

    # Act
    await manager.create()
    response = await manager.update(did, did_doc)

    # Assert
    assert response["did"] == "did:cheqd:testnet:123456"
    assert response["didDocument"]["MOCK_KEY"] == "MOCK_VALUE_UPDATED"

    mock_registrar_instance.return_value.update.assert_has_calls(
        [
            call(
                {
                    "did": did,
                    "didDocumentOperation": ["setDidDocument"],
                    "didDocument": [did_doc],
                }
            ),
            call(
                {
                    "jobId": "MOCK_ID",
                    "secret": {
                        "signingResponse": [{"kid": "MOCK_KID", "signature": ANY}]
                    },
                }
            ),
        ]
    )


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDResolver")
@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_update_with_did_deactivated(
    mock_registrar_instance, mock_resolver_instance, profile
):
    # Arrange
    did = "did:cheqd:testnet:123456"
    did_doc = {"MOCK_KEY": "MOCK_VALUE"}

    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
        registrar_update_responses,
    )
    setup_mock_resolver(mock_resolver_instance.return_value, {"deactivated": True})

    manager = CheqdDIDManager(profile)

    # Act
    await manager.create()

    with pytest.raises(Exception) as e:
        await manager.update(did, did_doc)

    # Assert
    assert isinstance(e.value, DIDNotFound)
    assert str(e.value) == "DID is already deactivated or not found."


@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDResolver")
@patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
@pytest.mark.asyncio
async def test_update_with_signing_failure(
    mock_registrar_instance,
    mock_resolver_instance,
    profile,
):
    # Arrange
    did = "did:cheqd:testnet:123456"
    did_doc = {"MOCK_KEY": "MOCK_VALUE"}

    setup_mock_registrar(
        mock_registrar_instance.return_value,
        registrar_generate_did_doc_response,
        registrar_create_responses,
        registrar_responses_no_signing_request,
    )
    setup_mock_resolver(mock_resolver_instance.return_value)

    manager = CheqdDIDManager(profile)

    # Act
    await manager.create()

    with pytest.raises(Exception) as e:
        await manager.update(did, did_doc)

    # Assert
    assert isinstance(e.value, Exception)
    assert str(e.value) == "No signing requests available for update."
