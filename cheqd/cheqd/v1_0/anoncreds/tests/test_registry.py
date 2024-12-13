from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
)
from acapy_agent.anoncreds.models.schema import GetSchemaResult, SchemaResult

from ....v1_0.validation import CHEQD_DID_VALIDATE
from ..registry import DIDCheqdRegistry

TEST_CHEQD_DID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c"
TEST_CHEQD_SCHEMA_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/e788d345-dd0c-427a-a74b-27faf1e608cd"
TEST_CHEQD_CRED_DEF_ID = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c/resources/02229804-b46a-4be9-a6f1-13869109c7ea"
TEST_CHEQD_REV_REG_ENTRY = "did:cheqd:testnet:1686a962-6e82-46f3-bde7-e6711d63958c?resourceName=test&resourceType=anoncredsRevRegEntry"


async def test_supported_did_regex():
    registry = DIDCheqdRegistry()

    assert registry.supported_identifiers_regex == CHEQD_DID_VALIDATE.PATTERN
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_DID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_SCHEMA_ID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_CRED_DEF_ID))
    assert bool(registry.supported_identifiers_regex.match(TEST_CHEQD_REV_REG_ENTRY))


async def test_make_schema_id():
    # Arrange
    schema = MagicMock()
    schema.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    schema_id = DIDCheqdRegistry.make_schema_id(schema, resource_id)

    # Assert
    assert schema_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_make_credential_definition_id():
    # Arrange
    credential_definition = MagicMock()
    credential_definition.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    credential_definition_id = DIDCheqdRegistry.make_credential_definition_id(
        credential_definition, resource_id
    )

    # Assert
    assert credential_definition_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_make_revocation_registry_id():
    # Arrange
    revocation_registry_definition = MagicMock()
    revocation_registry_definition.issuer_id = "MOCK_ID"
    resource_id = "MOCK_RESOURCE_ID"

    # Act
    revocation_registry_id = DIDCheqdRegistry.make_revocation_registry_id(
        revocation_registry_definition, resource_id
    )

    # Assert
    assert revocation_registry_id == "MOCK_ID/resources/MOCK_RESOURCE_ID"


async def test_split_schema_id():
    # Arrange
    schema_id = "PART0/PART1/PART2"

    # Act
    result = DIDCheqdRegistry.split_schema_id(schema_id)

    # Assert
    assert result == ("PART0", "PART2")


async def test_get_schema():
    # Arrange
    schema_id = "PART0/PART1/PART2"
    profile = MagicMock()
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
        "attrNames": "MOCK_attrNames",
        "name": "MOCK_name",
        "version": "MOCK_version",
    }
    mock_resolver.resolve_resource.return_value.metadata = {
        "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_schema(profile=profile, schema_id=schema_id)

        # Assert
        assert isinstance(result, GetSchemaResult)
        assert result.schema_id == schema_id
        assert result.schema.issuer_id == "PART0"
        assert result.schema.attr_names == "MOCK_attrNames"
        assert result.schema.name == "MOCK_name"
        assert result.schema.version == "MOCK_version"
        assert result.schema_metadata == {"MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"}
        assert result.resolution_metadata == {}
        mock_resolver.resolve_resource.assert_called_once_with(schema_id)


async def test_register_schema():
    # Arrange
    profile = MagicMock()
    schema = MagicMock()
    schema.issuer_id = "MOCK_issuer_id"
    schema.name = "MOCK_name"
    schema.version = "MOCK_version"
    schema.attr_names = "MOCK_attrNames"

    mock_create_and_publish_resource = {
        "jobId": "MOCK_JOB_ID",
        "resource": {"id": "MOCK_RESOURCE"},
        "id": "MOCK_ID",
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
        return_value=mock_create_and_publish_resource,
    ) as mock:
        registry = DIDCheqdRegistry()
        result = await registry.register_schema(profile=profile, schema=schema)

        # Assert
        assert isinstance(result, SchemaResult)
        assert result.job_id == "MOCK_JOB_ID"
        assert result.schema_state.state == "finished"
        assert result.schema_state.schema_id == "MOCK_issuer_id/resources/MOCK_RESOURCE"
        assert result.schema_state.schema == schema
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE"
        assert result.registration_metadata["resource_name"] == "MOCK_name"
        assert result.registration_metadata["resource_type"] == "anonCredsSchema"

        mock.assert_called_once_with(
            profile,
            "http://localhost:3000/1.0/",
            "http://localhost:8080/1.0/identifiers/",
            "MOCK_issuer_id",
            {
                "name": "MOCK_name",
                "type": "anonCredsSchema",
                "version": "MOCK_version",
                "data": ANY,
            },
        )


async def test_register_schema_registration_error():
    # Arrange
    profile = MagicMock()
    schema = MagicMock()
    schema.issuer_id = "MOCK_issuer_id"
    schema.name = "MOCK_name"
    schema.version = "MOCK_version"
    schema.attr_names = "MOCK_attrNames"

    mock_create_and_publish_resource = AsyncMock()
    mock_create_and_publish_resource.side_effect = Exception("Error")

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
        mock_create_and_publish_resource,
    ):
        with pytest.raises(Exception) as e:
            registry = DIDCheqdRegistry()
            await registry.register_schema(profile=profile, schema=schema)

        # Assert
        assert "Error" in str(e.value)
        assert isinstance(e.value, AnonCredsRegistrationError)
