import pytest
from aioresponses import aioresponses
from yarl import URL

from ..registrar import CheqdDIDRegistrar


@pytest.mark.asyncio
async def test_generate_did_doc(common_params, mock_did_document_url):
    # Arrange
    mock_did_document_response = {"MOCK_KEY": "MOCK_VALUE"}

    with aioresponses() as mocked:
        registrar = CheqdDIDRegistrar(registrar_url=common_params["registrar_url"])
        mocked.get(mock_did_document_url, status=200, payload=mock_did_document_response)

        # Act
        did_doc = await registrar.generate_did_doc(
            common_params["network"], common_params["public_key_hex"]
        )

        # Assert
        assert did_doc is not None
        assert did_doc["MOCK_KEY"] == "MOCK_VALUE"

        expected_params = {
            "methodSpecificIdAlgo": "uuid",
            "network": common_params["network"],
            "publicKeyHex": common_params["public_key_hex"],
            "verificationMethod": "Ed25519VerificationKey2020",
        }
        request_call = mocked.requests[("GET", mock_did_document_url)][0]
        assert request_call.kwargs["params"] == expected_params


@pytest.mark.asyncio
async def test_generate_did_doc_unhappy(common_params, mock_did_document_url):
    # Arrange
    with aioresponses() as mocked:
        mocked.get(mock_did_document_url, status=404)
        registrar = CheqdDIDRegistrar(registrar_url=common_params["registrar_url"])

        # Act
        with pytest.raises(Exception) as excinfo:
            await registrar.generate_did_doc(
                common_params["network"], common_params["public_key_hex"]
            )

        # Assert
        assert "404" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create(common_params):
    # Arrange
    create_url = common_params["registrar_url"] + "create"
    create_options = {"MOCK_KEY": "MOCK_VALUE"}
    mock_response = {"MOCK_KEY": "MOCK_VALUE"}

    with aioresponses() as mocked:
        mocked.post(create_url, status=201, payload=mock_response)
        registrar = CheqdDIDRegistrar(registrar_url=common_params["registrar_url"])

        # Act
        response = await registrar.create(create_options)

        # Assert
        assert response is not None
        assert response["MOCK_KEY"] == "MOCK_VALUE"

        request_call = mocked.requests[("POST", URL(create_url))][0]
        assert request_call.kwargs["json"] == create_options
