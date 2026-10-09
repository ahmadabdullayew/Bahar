from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _resource_directory(name: str, environment_name: str) -> Path:
    configured = os.environ.get(environment_name)
    candidates = [Path(configured)] if configured else []
    candidates.extend((PROJECT_ROOT / name, Path.cwd() / name, Path(__file__).resolve().parent / name))
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    # Preserve a deterministic path in the eventual error message.
    return candidates[0]


DATA_DIR = _resource_directory("data", "BAHAR_DATA_DIR")
WEB_DIR = _resource_directory("web", "BAHAR_WEB_DIR")


def load_json(name: str) -> Any:
    return json.loads((DATA_DIR / name).read_text(encoding="utf-8"))


def load_case(name: str) -> dict[str, Any]:
    case = load_json(name)
    if not case.get("rules"):
        case["rules"] = load_json("az_rules.json")
    return case

