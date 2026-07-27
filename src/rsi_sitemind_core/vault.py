from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .canonical import sha256_hex
from .work_os import MissionWorkspace


@dataclass(frozen=True)
class VaultValidationResult:
    valid: bool
    errors: tuple[str, ...]
    warnings: tuple[str, ...]


class CANAVault:
    REQUIRED_DIRECTORIES = (
        "00_SYSTEM", "01_PROJECTS", "02_PEOPLE_AND_ORGANIZATIONS", "03_RESEARCH",
        "04_DECISIONS", "05_SKILLS", "06_PLUGINS", "07_EVALUATIONS", "08_RECEIPTS",
        "09_DAILY", "10_PREFERENCES", "11_SECURITY", "12_ARCHIVE",
    )
    SECRET_PATTERNS = (
        re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.+=]{16,}"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    )

    @classmethod
    def initialize(cls, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        for directory in cls.REQUIRED_DIRECTORIES:
            (root / directory).mkdir(exist_ok=True)
        manifest = {
            "schema_version": "cana-vault-1.0.0",
            "required_directories": cls.REQUIRED_DIRECTORIES,
            "content_addressing": "sha256",
            "production_skill_self_modification": False,
        }
        (root / "00_SYSTEM" / "VAULT_MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    @staticmethod
    def create_mission_workspace(root: Path, mission: MissionWorkspace) -> Path:
        mission_root = root / "01_PROJECTS" / mission.project / "missions" / mission.mission_id
        mission_root.mkdir(parents=True, exist_ok=False)
        headings = {
            "GOAL.md": "# Goal\n\n## Objective\n\n## Observable Outcomes\n\n## Acceptance Tests\n\n## Failure Conditions\n\n## Completion Evidence\n",
            "PLAN.md": "# Plan\n\n## Strategy\n\n## Dependencies\n\n## Trade-offs\n\n## Milestones\n\n## Verification Points\n",
            "WORKLOG.md": "# Work Log\n\nRecord timestamp, actor, task, files/systems touched, result, evidence, errors, unresolved questions, and next step.\n",
            "RECEIPTS.md": "# Receipts\n\nNo completion claim is valid without independently reviewable evidence.\n",
            "DECISIONS.md": "# Decisions\n\nRecord decision, evidence, alternatives, owner, date, and supersession state.\n",
            "RISKS.md": "# Risks\n\nRecord likelihood, impact, mitigation, owner, and trigger.\n",
            "OPEN_GAPS.md": "# Open Gaps\n\nSeparate blocked, proposed, credential-dependent, and approval-dependent work.\n",
            "ROLLBACK.md": "# Rollback\n\nRecord checkpoint, trigger, procedure, verification, and recovery owner.\n",
        }
        for name, content in headings.items():
            (mission_root / name).write_text(content, encoding="utf-8")
        (mission_root / "MISSION.json").write_text(json.dumps(asdict(mission), indent=2, default=lambda value: value.value) + "\n", encoding="utf-8")
        return mission_root

    @staticmethod
    def store_artifact(root: Path, data: bytes, suffix: str = "bin") -> Path:
        digest = sha256_hex({"bytes_hex": data.hex()})
        path = root / "08_RECEIPTS" / "artifacts" / digest[:2] / f"{digest}.{suffix.lstrip('.')}"
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
        return path

    @classmethod
    def validate(cls, root: Path, *, scan_paths: Iterable[Path] | None = None) -> VaultValidationResult:
        errors: list[str] = []
        warnings: list[str] = []
        for directory in cls.REQUIRED_DIRECTORIES:
            if not (root / directory).is_dir():
                errors.append(f"missing_directory:{directory}")
        manifest = root / "00_SYSTEM" / "VAULT_MANIFEST.json"
        if not manifest.is_file():
            errors.append("missing_manifest")
        paths = list(scan_paths) if scan_paths is not None else [p for p in root.rglob("*") if p.is_file()]
        for path in paths:
            try:
                if path.stat().st_size > 2_000_000:
                    warnings.append(f"secret_scan_skipped_large_file:{path}")
                    continue
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for pattern in cls.SECRET_PATTERNS:
                if pattern.search(text):
                    errors.append(f"possible_secret:{path}")
                    break
        return VaultValidationResult(not errors, tuple(sorted(errors)), tuple(sorted(warnings)))
