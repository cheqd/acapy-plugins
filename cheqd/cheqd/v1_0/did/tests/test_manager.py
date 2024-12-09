import logging
from unittest.async_case import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

import pytest
from acapy_agent.cache.base import BaseCache
from acapy_agent.cache.in_memory import InMemoryCache
from acapy_agent.utils.testing import create_test_profile
from acapy_agent.wallet.did_method import DIDMethods
from acapy_agent.wallet.error import WalletError
from acapy_agent.wallet.key_type import KeyTypes

from ...did.base import CheqdDIDManagerError
from ...did_method import CHEQD
from ..manager import CheqdDIDManager


class TestCheqdDidManager(IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        did_methods = DIDMethods()
        did_methods.register(CHEQD)
        self.profile = await create_test_profile(
            settings={"wallet.type": "askar-anoncreds"},
        )
        self.profile.context.injector.bind_instance(DIDMethods, did_methods)
        self.profile.context.injector.bind_instance(KeyTypes, KeyTypes())
        self.logger = logging.getLogger(__name__)
        self.profile.context.injector.bind_instance(BaseCache, InMemoryCache())

        self.mock_registrar_generate_did_doc = {
            "didDoc": {
                "id": "did:cheqd:testnet:123456",
                "verificationMethod": {"publicKey": "someVerificationKey"},
            }
        }

        self.mock_registrar_create = iter(
            [
                {
                    "jobId": "MOCK_ID",
                    "didState": {
                        "state": "action",
                        "signingRequest": [
                            {"kid": "MOCK_KID", "serializedPayload": "MOCK"}
                        ],
                    },
                },
                {
                    "jobId": "MOCK_ID",
                    "didState": {"state": "finished"},
                },
            ]
        )

    @patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
    async def test_create_did(self, mock_CheqdDIDRegistrar):
        mock_registrar_instance = mock_CheqdDIDRegistrar.return_value
        mock_registrar_instance.generate_did_doc = AsyncMock(
            return_value=self.mock_registrar_generate_did_doc
        )
        mock_registrar_instance.create = AsyncMock()
        mock_registrar_instance.create.side_effect = self.mock_registrar_create

        manager = CheqdDIDManager(self.profile)

        response = await manager.create()

        assert response["did"] == "did:cheqd:testnet:123456"
        print(f"DID created: {response}")

    @patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
    async def test_create_did_with_insecure_seed(self, mock_CheqdDIDRegistrar):
        mock_registrar_instance = mock_CheqdDIDRegistrar.return_value
        mock_registrar_instance.generate_did_doc = AsyncMock(
            return_value=self.mock_registrar_generate_did_doc
        )
        mock_registrar_instance.create = AsyncMock()
        mock_registrar_instance.create.side_effect = self.mock_registrar_create

        self.profile.settings["wallet.allow_insecure_seed"] = False
        manager = CheqdDIDManager(self.profile)

        options = {"seed": "insecure-seed"}
        with pytest.raises(Exception) as e:
            await manager.create(options=options)

        assert isinstance(e.value, WalletError)

    @patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
    async def test_create_did_with_invalid_did_document(self, mock_CheqdDIDRegistrar):
        mock_registrar_instance = mock_CheqdDIDRegistrar.return_value
        mock_registrar_instance.generate_did_doc = AsyncMock(return_value=None)
        mock_registrar_instance.create = AsyncMock()
        mock_registrar_instance.create.side_effect = self.mock_registrar_create

        manager = CheqdDIDManager(self.profile)

        with pytest.raises(Exception) as e:
            await manager.create()

        assert isinstance(e.value, CheqdDIDManagerError)
        assert str(e.value) == "Error constructing DID Document"

    @patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
    async def test_create_did_with_signing_failure(self, mock_CheqdDIDRegistrar):
        mock_registrar_instance = mock_CheqdDIDRegistrar.return_value
        mock_registrar_instance.generate_did_doc = AsyncMock(
            return_value=self.mock_registrar_generate_did_doc
        )
        mock_registrar_instance.create = AsyncMock()
        mock_registrar_instance.create.side_effect = iter(
            [
                {
                    "jobId": "MOCK_ID",
                    "didState": {
                        "state": "action",
                        "signingRequest": [],
                    },
                },
            ]
        )

        manager = CheqdDIDManager(self.profile)

        with pytest.raises(Exception) as e:
            await manager.create()

        assert isinstance(e.value, CheqdDIDManagerError)
        assert str(e.value) == "No signing requests available for create."

    @patch("cheqd.cheqd.v1_0.did.manager.CheqdDIDRegistrar")
    async def test_create_did_with_registration_failure(self, mock_CheqdDIDRegistrar):
        mock_registrar_instance = mock_CheqdDIDRegistrar.return_value
        mock_registrar_instance.generate_did_doc = AsyncMock(
            return_value=self.mock_registrar_generate_did_doc
        )
        mock_registrar_instance.create = AsyncMock()
        mock_registrar_instance.create.side_effect = iter(
            [
                {
                    "jobId": "MOCK_ID",
                    "didState": {
                        "state": "error",
                        "reason": "Network failure",
                    },
                },
            ]
        )

        manager = CheqdDIDManager(self.profile)

        with pytest.raises(Exception) as e:
            await manager.create()

        assert isinstance(e.value, CheqdDIDManagerError)
        assert str(e.value) == "Error registering DID Network failure"
