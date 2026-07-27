from pathlib import Path

from rsi_sitemind_core.vault import CANAVault
from rsi_sitemind_core.work_os import AutonomyLevel, MissionStatus, MissionWorkspace


def mission():
    return MissionWorkspace(
        mission_id="cana-work-os", title="CANA Work OS", owner="Hermes", project="CANA",
        objective="Build canonical work OS", status=MissionStatus.PLANNED, priority=100,
        autonomy_level=AutonomyLevel.DRAFT, allowed_tools=("filesystem",),
        allowed_data_sources=("repos",), blocked_actions=("production-deploy",), dependencies=(),
        success_criteria=("validator passes",), verification_method=("pytest",),
        rollback_method=("delete branch",),
    )


def test_vault_initialization_workspace_and_artifact_are_deterministic(tmp_path: Path):
    root = tmp_path / "CANA_VAULT"
    CANAVault.initialize(root)
    workspace = CANAVault.create_mission_workspace(root, mission())
    for filename in MissionWorkspace.REQUIRED_FILES:
        assert (workspace / filename).is_file()
    first = CANAVault.store_artifact(root, b"receipt", "txt")
    second = CANAVault.store_artifact(root, b"receipt", "txt")
    assert first == second and first.read_bytes() == b"receipt"
    assert CANAVault.validate(root).valid


def test_vault_secret_scan_fails_closed(tmp_path: Path):
    root = tmp_path / "CANA_VAULT"
    CANAVault.initialize(root)
    leaked = root / "11_SECURITY" / "bad.txt"
    leaked.write_text("api_key = 'abcdefghijklmnop1234567890'", encoding="utf-8")
    result = CANAVault.validate(root)
    assert not result.valid
    assert any(error.startswith("possible_secret:") for error in result.errors)
