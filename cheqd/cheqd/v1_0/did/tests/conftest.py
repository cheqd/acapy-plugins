import pytest
from yarl import URL


@pytest.fixture
def common_params():
    return {
        "registrar_url": "http://localhost:3000/1.0/",
        "network": "testnet",
        "public_key_hex": "abc123",
    }


@pytest.fixture
def mock_did_document_url(common_params):
    return URL(common_params["registrar_url"] + "did-document").with_query(
        {
            "methodSpecificIdAlgo": "uuid",
            "network": common_params["network"],
            "publicKeyHex": common_params["public_key_hex"],
            "verificationMethod": "Ed25519VerificationKey2020",
        }
    )


@pytest.fixture
def mock_options():
    return {"MOCK_KEY": "MOCK_VALUE"}


@pytest.fixture
def mock_response():
    return {"MOCK_KEY": "MOCK_VALUE"}
