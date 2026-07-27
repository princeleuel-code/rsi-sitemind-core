from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import unicodedata
import zipfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator

from jsonschema import Draft202012Validator

from .canonical import sha256_hex
from .work_os import MissionWorkspace

try:
    import fcntl
except ImportError:
    fcntl = None


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
    MANIFEST_SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "required_directories", "content_addressing", "production_skill_self_modification", "secret_reference_scheme"],
        "properties": {
            "schema_version": {"const": "cana-vault-1.1.0"},
            "required_directories": {"type": "array", "items": {"type": "string"}, "uniqueItems": True},
            "content_addressing": {"const": "sha256"},
            "production_skill_self_modification": {"const": False},
            "secret_reference_scheme": {"const": "secret://"},
        },
    }
    SECRET_PATTERNS = (
        re.compile(r"(?i)-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(r"(?i)\b(?:api[_-]?key|secret|password|access[_-]?token)\b\s*[:=]\s*['\"]?(?!secret://)[A-Za-z0-9_\-/.+=]{16,}"),
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    )
    MAX_TEXT_BYTES = 2_000_000
    MAX_ARCHIVE_UNCOMPRESSED_BYTES = 50_000_000
    MAX_ARCHIVE_RATIO = 100

    @staticmethod
    def _safe_segment(value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value)
        if normalized != value or not re.fullmatch(r"[A-Za-z0-9._-]+", value) or value in {".", ".."}:
            raise ValueError("unsafe or non-canonical path segment")
        return value

    @classmethod
    def safe_path(cls, root: Path, relative: str | Path, *, allow_missing: bool = True) -> Path:
        root = root.resolve()
        raw = PurePosixPath(str(relative).replace(os.sep, "/"))
        if raw.is_absolute() or ".." in raw.parts:
            raise ValueError("path traversal denied")
        for part in raw.parts:
            cls._safe_segment(part)
        candidate = root.joinpath(*raw.parts)
        cursor = root
        for part in raw.parts:
            cursor = cursor / part
            if cursor.exists() and cursor.is_symlink():
                raise PermissionError("symlink path denied")
        resolved_parent = candidate.parent.resolve(strict=False)
        if root != resolved_parent and root not in resolved_parent.parents:
            raise PermissionError("vault path escape denied")
        if not allow_missing and not candidate.exists():
            raise FileNotFoundError(candidate)
        return candidate

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data); handle.flush(); os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        finally:
            if os.path.exists(tmp_name): os.unlink(tmp_name)

    @classmethod
    @contextmanager
    def _lock(cls, root: Path) -> Iterator[None]:
        lock_path = cls.safe_path(root, "00_SYSTEM/.vault.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if fcntl is not None: fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None: fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    @classmethod
    def initialize(cls, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink(): raise PermissionError("vault root cannot be a symlink")
        for directory in cls.REQUIRED_DIRECTORIES: cls.safe_path(root, directory).mkdir(exist_ok=True)
        manifest = {"schema_version": "cana-vault-1.1.0", "required_directories": list(cls.REQUIRED_DIRECTORIES), "content_addressing": "sha256", "production_skill_self_modification": False, "secret_reference_scheme": "secret://"}
        cls._atomic_write(cls.safe_path(root, "00_SYSTEM/VAULT_MANIFEST.json"), (json.dumps(manifest, indent=2) + "\n").encode())

    @classmethod
    def create_mission_workspace(cls, root: Path, mission: MissionWorkspace) -> Path:
        mission_root = cls.safe_path(root, f"01_PROJECTS/{cls._safe_segment(mission.project)}/missions/{cls._safe_segment(mission.mission_id)}")
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
        for name, content in headings.items(): cls._atomic_write(mission_root / name, content.encode())
        cls._atomic_write(mission_root / "MISSION.json", (json.dumps(asdict(mission), indent=2, default=lambda value: value.value) + "\n").encode())
        return mission_root

    @classmethod
    def append_worklog(cls, root: Path, mission: MissionWorkspace, entry: str) -> str:
        if not entry.strip() or "\x00" in entry: raise ValueError("valid worklog entry required")
        path = cls.safe_path(root, f"01_PROJECTS/{cls._safe_segment(mission.project)}/missions/{cls._safe_segment(mission.mission_id)}/WORKLOG.md", allow_missing=False)
        with cls._lock(root):
            with path.open("ab") as handle:
                handle.write((entry.rstrip() + "\n").encode()); handle.flush(); os.fsync(handle.fileno())
        return sha256_hex({"entry": entry.rstrip()})

    @classmethod
    def store_artifact(cls, root: Path, data: bytes, suffix: str = "bin") -> Path:
        if len(data) > cls.MAX_ARCHIVE_UNCOMPRESSED_BYTES: raise ValueError("artifact too large")
        digest = sha256_hex({"bytes_hex": data.hex()})
        path = cls.safe_path(root, f"08_RECEIPTS/artifacts/{digest[:2]}/{digest}.{cls._safe_segment(suffix.lstrip('.'))}")
        with cls._lock(root):
            if path.exists():
                if path.read_bytes() != data: raise RuntimeError("content-address collision or artifact tampering")
            else: cls._atomic_write(path, data)
        return path

    @classmethod
    def verify_artifact(cls, path: Path) -> bool:
        match = re.fullmatch(r"([a-f0-9]{64})\.[A-Za-z0-9_-]+", path.name)
        return bool(match and match.group(1) == sha256_hex({"bytes_hex": path.read_bytes().hex()}))

    @classmethod
    def inspect_archive(cls, archive_path: Path) -> VaultValidationResult:
        errors: list[str] = []
        with zipfile.ZipFile(archive_path) as archive:
            total = 0
            for info in archive.infolist():
                raw = PurePosixPath(info.filename)
                if raw.is_absolute() or ".." in raw.parts: errors.append(f"archive_path_escape:{info.filename}")
                total += info.file_size
                if info.file_size > 0 and info.compress_size > 0 and info.file_size / info.compress_size > cls.MAX_ARCHIVE_RATIO: errors.append(f"archive_compression_bomb:{info.filename}")
            if total > cls.MAX_ARCHIVE_UNCOMPRESSED_BYTES: errors.append("archive_uncompressed_size_exceeded")
        return VaultValidationResult(not errors, tuple(sorted(errors)), ())

    @classmethod
    def backup(cls, root: Path, destination: Path) -> str:
        if not cls.validate(root).valid: raise PermissionError("invalid vault cannot be backed up")
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_symlink(): raise PermissionError("symlink cannot enter backup")
                if path.is_file() and path.name != ".vault.lock": archive.write(path, path.relative_to(root).as_posix())
        return sha256_hex({"bytes_hex": destination.read_bytes().hex()})

    @classmethod
    def restore(cls, archive_path: Path, destination: Path) -> None:
        if not cls.inspect_archive(archive_path).valid: raise PermissionError("unsafe vault backup")
        if destination.exists() and any(destination.iterdir()): raise FileExistsError("restore destination must be empty")
        destination.mkdir(parents=True, exist_ok=True)
        for directory in cls.REQUIRED_DIRECTORIES: cls.safe_path(destination, directory).mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                target = cls.safe_path(destination, info.filename)
                if info.is_dir(): target.mkdir(parents=True, exist_ok=True)
                else: cls._atomic_write(target, archive.read(info))
        if not cls.validate(destination).valid:
            shutil.rmtree(destination); raise ValueError("restored vault failed validation")

    @classmethod
    def validate(cls, root: Path, *, scan_paths: Iterable[Path] | None = None) -> VaultValidationResult:
        errors: list[str] = []; warnings: list[str] = []
        if root.is_symlink(): errors.append("vault_root_symlink")
        for directory in cls.REQUIRED_DIRECTORIES:
            path = root / directory
            if not path.is_dir() or path.is_symlink(): errors.append(f"missing_or_unsafe_directory:{directory}")
        manifest = root / "00_SYSTEM" / "VAULT_MANIFEST.json"
        if not manifest.is_file(): errors.append("missing_manifest")
        else:
            try:
                parsed = json.loads(manifest.read_text(encoding="utf-8"))
                for error in Draft202012Validator(cls.MANIFEST_SCHEMA).iter_errors(parsed): errors.append(f"manifest_schema:{error.json_path}:{error.message}")
            except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc: errors.append(f"manifest_invalid:{type(exc).__name__}")
        paths = list(scan_paths) if scan_paths is not None else [p for p in root.rglob("*") if p.is_file()]
        for path in paths:
            try:
                if path.is_symlink(): errors.append(f"symlink_file:{path}"); continue
                if unicodedata.normalize("NFKC", path.name) != path.name: errors.append(f"noncanonical_filename:{path}")
                if path.stat().st_size > cls.MAX_TEXT_BYTES: warnings.append(f"text_scan_skipped_large_file:{path}"); continue
                text = path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError): continue
            if any(unicodedata.category(ch) in {"Cf", "Cs"} for ch in text): errors.append(f"unicode_control_character:{path}")
            for pattern in cls.SECRET_PATTERNS:
                if pattern.search(text): errors.append(f"possible_secret:{path}"); break
        artifact_root = root / "08_RECEIPTS" / "artifacts"
        if artifact_root.exists():
            for artifact in artifact_root.rglob("*"):
                if artifact.is_file() and not cls.verify_artifact(artifact): errors.append(f"artifact_digest_mismatch:{artifact}")
        return VaultValidationResult(not errors, tuple(sorted(set(errors))), tuple(sorted(set(warnings))))
