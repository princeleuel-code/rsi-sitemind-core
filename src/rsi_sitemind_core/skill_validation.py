from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from jsonschema import Draft202012Validator


@dataclass(frozen=True)
class SkillDocumentValidation:
    valid: bool
    errors: tuple[str, ...]


class SkillRegistryDocumentValidator:
    SCHEMA: Mapping[str, Any] = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "additionalProperties": False,
        "required": ["schema_version", "authority", "production_self_promotion", "skills"],
        "properties": {
            "schema_version": {"type": "string", "minLength": 1},
            "authority": {"const": "proposal-only"},
            "production_self_promotion": {"const": False},
            "skills": {"type": "array", "items": {"type": "object", "additionalProperties": False, "required": ["id", "project", "version", "status"], "properties": {"id": {"type": "string", "pattern": "^[a-z0-9-]+$"}, "project": {"type": "string", "minLength": 1}, "version": {"type": "string", "pattern": "^\\d+\\.\\d+\\.\\d+$"}, "status": {"enum": ["candidate", "planned", "deprecated"]}}}}
        },
    }

    def validate(self, document: Mapping[str, Any]) -> SkillDocumentValidation:
        errors = [f"{error.json_path}:{error.message}" for error in Draft202012Validator(self.SCHEMA).iter_errors(document)]
        ids = [item.get("id") for item in document.get("skills", []) if isinstance(item, dict)]
        if len(ids) != len(set(ids)):
            errors.append("duplicate_skill_id")
        return SkillDocumentValidation(not errors, tuple(sorted(errors)))
