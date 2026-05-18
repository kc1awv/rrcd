from __future__ import annotations

from pathlib import Path

import pytest

from rrcd.cli import _build_arg_parser, _write_default_config
from rrcd.constants import HUB_DEST_NAME


def test_arg_parser_rejects_dest_name_override() -> None:
    parser = _build_arg_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["--dest-name", "custom.hub"])


def test_default_config_does_not_emit_dest_name_field(tmp_path: Path) -> None:
    config_path = tmp_path / "rrcd.toml"
    identity_path = tmp_path / "hub_identity"

    _write_default_config(str(config_path), str(identity_path))

    content = config_path.read_text(encoding="utf-8")
    assert "dest_name =" not in content
    assert f"Hubs always announce on {HUB_DEST_NAME!r}." in content