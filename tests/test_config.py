from __future__ import annotations

import logging

from rrcd.config import ConfigManager, HubRuntimeConfig
from rrcd.constants import HUB_DEST_NAME
from rrcd.service import HubService


class _FakeHub:
    def __init__(self) -> None:
        self.log = logging.getLogger("test")
        self.config = HubRuntimeConfig()


def test_apply_config_data_ignores_dest_name_override() -> None:
    manager = ConfigManager(_FakeHub())
    base = HubRuntimeConfig()

    updated = manager.apply_config_data(
        base,
        {
            "dest_name": "custom.hub",
            "hub": {"dest_name": "custom.hub"},
            "hub_name": "custom-name",
        },
    )

    assert updated.dest_name == HUB_DEST_NAME
    assert updated.hub_name == "custom-name"


def test_service_normalizes_custom_dest_name() -> None:
    service = HubService(HubRuntimeConfig(dest_name="custom.hub"))

    assert service.config.dest_name == HUB_DEST_NAME