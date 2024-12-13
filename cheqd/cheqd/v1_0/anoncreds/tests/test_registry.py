import time
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from acapy_agent.anoncreds.base import (
    AnonCredsRegistrationError,
)
from acapy_agent.anoncreds.models.credential_definition import (
    CredDefResult,
    GetCredDefResult,
)
from acapy_agent.anoncreds.models.revocation import (
    GetRevListResult,
    GetRevRegDefResult,
    RevListResult,
    RevRegDefResult,
)
from acapy_agent.anoncreds.models.schema import GetSchemaResult, SchemaResult
from acapy_agent.anoncreds.models.schema_info import AnoncredsSchemaInfo

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


async def test_get_credential_definition():
    # Arrange
    profile = MagicMock()
    credential_definition_id = "PART0/PART1/PART2"
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
        "schemaId": "MOCK_schemaId",
        "type": "MOCK_type",
        "tag": "MOCK_tag",
        "value": {"MOCK_KEY": "MOCK_VALUE"},
    }
    mock_resolver.resolve_resource.return_value.metadata = {
        "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ), patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CredDefValue.deserialize",
        return_value={"MOCK_KEY": "MOCK_VALUE"},
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_credential_definition(
            profile, credential_definition_id
        )

        # Assert
        assert isinstance(result, GetCredDefResult)
        assert result.credential_definition_id == credential_definition_id
        assert result.credential_definition.issuer_id == "PART0"
        assert result.credential_definition.schema_id == "MOCK_schemaId"
        assert result.credential_definition.type == "MOCK_type"
        assert result.credential_definition.tag == "MOCK_tag"
        assert result.credential_definition.value == {"MOCK_KEY": "MOCK_VALUE"}
        assert result.credential_definition_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }
        assert result.resolution_metadata == {}


async def test_register_credential_definition():
    # Arrange
    profile = MagicMock()
    schema = MagicMock()
    schema.schema_value.name = "MOCK_NAME"
    schema.schema_id = "MOCK_ID"
    credential_definition = MagicMock()
    credential_definition.issuer_id = "MOCK_ISSUER_ID"
    credential_definition.tag = "MOCK_TAG"
    credential_definition.type = "MOCK_TYPE"
    credential_definition.value = MagicMock()
    credential_definition.value.serialize.return_value = {
        "MOCK_KEY": "MOCK_VALUE_SERIALIZED"
    }

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
        result = await registry.register_credential_definition(
            profile, schema, credential_definition
        )

        # Assert
        assert isinstance(result, CredDefResult)
        assert result.job_id == "MOCK_JOB_ID"
        assert result.credential_definition_state.state == "finished"
        assert (
            result.credential_definition_state.credential_definition_id
            == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE"
        )
        assert (
            result.credential_definition_state.credential_definition
            == credential_definition
        )
        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE"
        assert result.registration_metadata["resource_name"] == "MOCK_NAME-MOCK_TAG"
        assert result.registration_metadata["resource_type"] == "anonCredsCredDef"

        mock.assert_called_once_with(
            profile,
            "http://localhost:3000/1.0/",
            "http://localhost:8080/1.0/identifiers/",
            "MOCK_ISSUER_ID",
            {
                "name": "MOCK_NAME-MOCK_TAG",
                "type": "anonCredsCredDef",
                "version": "MOCK_TAG",
                "data": ANY,
            },
        )


async def test_get_revocation_registry_definition():
    # Arrange
    profile = MagicMock()
    revocation_registry_id = "PART0/PART1/PART2"
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
        "credDefId": "MOCK_credDefId",
        "revocDefType": "MOCK_revocDefType",
        "tag": "MOCK_tag",
        "value": {"MOCK_KEY": "MOCK_VALUE"},
    }
    mock_resolver.resolve_resource.return_value.metadata = {
        "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ), patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.RevRegDefValue.deserialize",
        return_value={"MOCK_KEY": "MOCK_VALUE"},
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_revocation_registry_definition(
            profile, revocation_registry_id
        )

        # Assert
        assert isinstance(result, GetRevRegDefResult)
        assert result.revocation_registry_id == "PART0/PART1/PART2"
        assert result.revocation_registry.issuer_id == "PART0"
        assert result.revocation_registry.cred_def_id == "MOCK_credDefId"
        assert result.revocation_registry.type == "MOCK_revocDefType"
        assert result.revocation_registry.tag == "MOCK_tag"
        assert result.revocation_registry.value == {"MOCK_KEY": "MOCK_VALUE"}
        assert result.revocation_registry_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }
        assert result.resolution_metadata == {}
        mock_resolver.resolve_resource.assert_called_once_with("PART0/PART1/PART2")


async def test_register_revocation_registry_definition():
    # Arrange
    profile = MagicMock()
    rev_reg_def = MagicMock()
    rev_reg_def.cred_def_id = "MOCK_CRED_DEF_ID"
    rev_reg_def.issuer_id = "MOCK_ISSUER_ID"
    rev_reg_def.tag = "MOCK_TAG"
    rev_reg_def.type = "MOCK_TYPE"
    rev_reg_def.value.serialize.return_value = {"MOCK_KEY": "MOCK_VALUE"}

    cred_def_result = MagicMock()
    cred_def_result.credential_definition_metadata = {
        "resourceName": "MOCK_RESOURCE_NAME"
    }

    mock_create_and_publish_resource = {
        "jobId": "MOCK_JOB_ID",
        "resource": {"id": "MOCK_RESOURCE"},
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry.get_credential_definition",
        return_value=cred_def_result,
    ), patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
        return_value=mock_create_and_publish_resource,
    ) as mock:
        registry = DIDCheqdRegistry()
        result = await registry.register_revocation_registry_definition(
            profile, rev_reg_def
        )

        # Assert
        assert isinstance(result, RevRegDefResult)
        assert result.job_id == "MOCK_JOB_ID"
        assert result.revocation_registry_definition_state.state == "finished"
        assert (
            result.revocation_registry_definition_state.revocation_registry_definition_id
            == "MOCK_ISSUER_ID/resources/MOCK_RESOURCE"
        )
        assert (
            result.revocation_registry_definition_state.revocation_registry_definition
            == rev_reg_def
        )

        assert result.registration_metadata["resource_id"] == "MOCK_RESOURCE"
        assert result.registration_metadata["resource_name"] == "MOCK_TAG"
        assert result.registration_metadata["resource_type"] == "anonCredsRevocRegDef"
        assert result.revocation_registry_definition_metadata == {}
        mock.assert_called_once_with(
            profile,
            "MOCK_ISSUER_ID",
            {
                "name": "MOCK_RESOURCE_NAME-MOCK_TAG",
                "type": "anonCredsRevocRegDef",
                "version": "MOCK_TAG",
                "data": ANY,
            },
        )


async def test_get_revocation_list():
    # Arrange
    profile = MagicMock()
    revocation_registry_id = "PART0/PART1/PART2"
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
        "revocationList": [0, 1, 0],
        "currentAccumulator": "MOCK_ACCUMULATOR",
    }
    mock_resolver.resolve_resource.return_value.metadata = {
        "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
    }

    mock_revocation_registry_definition = MagicMock()
    mock_revocation_registry_definition.revocation_registry_metadata = {
        "resourceName": "MOCK_RESOURCE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ), patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
        AsyncMock(return_value=mock_revocation_registry_definition),
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_revocation_list(
            profile, revocation_registry_id, timestamp_to=int(time.time())
        )

        # Assert
        assert isinstance(result, GetRevListResult)
        assert result.revocation_list.issuer_id == "PART0"
        assert result.revocation_list.rev_reg_def_id == revocation_registry_id
        assert result.revocation_list.current_accumulator == "MOCK_ACCUMULATOR"
        assert result.revocation_list.revocation_list == [0, 1, 0]
        assert result.resolution_metadata == {}
        assert result.revocation_registry_metadata == {
            "MOCK_METADATA_KEY": "MOCK_METADATA_VALUE"
        }

        mock_resolver.resolve_resource.assert_called_once()


async def test_get_schema_info_by_id():
    # Arrange
    schema_id = "PART0/PART1/PART2"
    mock_resolver = AsyncMock()
    mock_resolver.resolve_resource.return_value = MagicMock()
    mock_resolver.resolve_resource.return_value.resource = {
        "name": "MOCK_NAME",
        "version": "MOCK_VERSION",
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.CheqdDIDResolver", return_value=mock_resolver
    ):
        registry = DIDCheqdRegistry()
        result = await registry.get_schema_info_by_id(schema_id)

        # Assert
        assert isinstance(result, AnoncredsSchemaInfo)
        assert result.issuer_id == "PART0"
        assert result.name == "MOCK_NAME"
        assert result.version == "MOCK_VERSION"
        mock_resolver.resolve_resource.assert_called_once_with(schema_id)


async def test_register_revocation_list():
    # Arrange
    profile = MagicMock()
    rev_list = MagicMock()
    rev_list.revocation_list = [0, 1, 0]
    rev_list.current_accumulator = "MOCK_ACCUMULATOR"
    rev_list.rev_reg_def_id = "MOCK_REV_REG_DEF_ID"

    rev_reg_def = MagicMock()
    rev_reg_def.issuer_id = "MOCK_ISSUER_ID"

    mock_create_and_publish_resource = {
        "jobId": "MOCK_JOB_ID",
        "resource": {"id": "MOCK_RESOURCE_ID"},
    }

    mock_revocation_registry_definition = MagicMock()
    mock_revocation_registry_definition.revocation_registry_metadata = {
        "resourceName": "MOCK_RESOURCE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
        AsyncMock(return_value=mock_revocation_registry_definition),
    ) as mock1, patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
        return_value=mock_create_and_publish_resource,
    ) as mock2:
        registry = DIDCheqdRegistry()
        result = await registry.register_revocation_list(profile, rev_reg_def, rev_list)

        # Assert
        assert isinstance(result, RevListResult)
        assert result.job_id == "MOCK_JOB_ID"
        assert result.revocation_list_state.state == "finished"
        assert result.revocation_list_state.revocation_list == rev_list
        assert result.registration_metadata == {}
        assert result.revocation_list_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.revocation_list_metadata["resource_name"] == "MOCK_RESOURCE"
        assert result.revocation_list_metadata["resource_type"] == "anonCredsStatusList"
        mock1.assert_called_once_with(profile, "MOCK_REV_REG_DEF_ID")
        mock2.assert_called_once_with(
            profile,
            "MOCK_ISSUER_ID",
            {
                "name": "MOCK_RESOURCE",
                "type": "anonCredsStatusList",
                "version": ANY,
                "data": ANY,
            },
        )


async def test_update_revocation_list():
    # Arrange
    profile = MagicMock()
    curr_list = MagicMock()
    curr_list.revocation_list = [0, 1, 0]
    curr_list.current_accumulator = "MOCK_ACCUMULATOR"
    curr_list.rev_reg_def_id = "MOCK_REV_REG_DEF_ID"

    rev_reg_def = MagicMock()
    rev_reg_def.issuer_id = "MOCK_ISSUER_ID"

    mock_create_and_publish_resource = {
        "jobId": "MOCK_JOB_ID",
        "resource": {"id": "MOCK_RESOURCE_ID"},
    }

    mock_revocation_registry_definition = MagicMock()
    mock_revocation_registry_definition.revocation_registry_metadata = {
        "resourceName": "MOCK_RESOURCE"
    }

    # Act
    with patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry.get_revocation_registry_definition",
        AsyncMock(return_value=mock_revocation_registry_definition),
    ) as mock1, patch(
        "cheqd.cheqd.v1_0.anoncreds.registry.DIDCheqdRegistry._create_and_publish_resource",
        return_value=mock_create_and_publish_resource,
    ) as mock2:
        registry = DIDCheqdRegistry()
        result = await registry.update_revocation_list(
            profile, rev_reg_def, None, curr_list, []
        )

        # Assert
        assert isinstance(result, RevListResult)
        assert result.job_id == "MOCK_JOB_ID"
        assert result.revocation_list_state.state == "finished"
        assert result.revocation_list_state.revocation_list == curr_list
        assert result.registration_metadata == {}
        assert result.revocation_list_metadata["resource_id"] == "MOCK_RESOURCE_ID"
        assert result.revocation_list_metadata["resource_name"] == "MOCK_RESOURCE"
        assert result.revocation_list_metadata["resource_type"] == "anonCredsStatusList"
        mock1.assert_called_once_with(profile, "MOCK_REV_REG_DEF_ID")
        mock2.assert_called_once_with(
            profile,
            "MOCK_ISSUER_ID",
            {
                "name": "MOCK_RESOURCE",
                "type": "anonCredsStatusList",
                "data": ANY,
                "version": ANY,
            },
        )
