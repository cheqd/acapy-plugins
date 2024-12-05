import pytest
from aioresponses import aioresponses
from yarl import URL

from ..registrar import CheqdDIDRegistrar


@pytest.fixture
def common_params():
    return {
        "registrar_url": "http://localhost:3000/1.0/",
        "network": "testnet",
        "public_key_hex": "abc123",
    }


@pytest.fixture
def mock_did_document_url(common_params):
    return URL(f"{common_params["registrar_url"]}did-document").with_query(
        {
            "verificationMethod": "Ed25519VerificationKey2020",
            "methodSpecificIdAlgo": "uuid",
            "network": common_params["network"],
            "publicKeyHex": common_params["public_key_hex"],
        }
    )


@pytest.fixture
def mock_did_document_response(common_params):
    did = "did:cheqd:testnet:123"
    return {
        "id": did,
        "controller": [did],
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyHex": common_params["public_key_hex"],
            }
        ],
        "authentication": [f"{did}#key-1"],
    }


@pytest.mark.asyncio
async def test_generate_did_doc(
    common_params,
    mock_did_document_response,
    mock_did_document_url,
):
    # Arrange
    with aioresponses() as mocked:
        registrar = CheqdDIDRegistrar(registrar_url=common_params["registrar_url"])
        mocked.get(mock_did_document_url, status=200, payload=mock_did_document_response)

        # Act
        did_doc = await registrar.generate_did_doc(
            common_params["network"], common_params["public_key_hex"]
        )

        # Assert
        expected_did = "did:cheqd:testnet:123"
        assert did_doc is not None
        assert did_doc["id"] == expected_did
        assert (
            did_doc["verificationMethod"][0]["publicKeyHex"]
            == common_params["public_key_hex"]
        )
        assert did_doc["authentication"] == [f"{expected_did}#key-1"]


@pytest.mark.asyncio
async def test_generate_did_doc_unhappy_path(common_params, mock_did_document_url):
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
