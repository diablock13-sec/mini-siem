import re
from dataclasses import dataclass
from functools import cache
from pathlib import Path

import yaml

DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")
BRUTE_FORCE_KEYS = {"threshold", "window_seconds", "login_paths", "statuses"}


class RulesError(ValueError):
    """Isi rules.yaml tidak valid."""


@dataclass(frozen=True)
class Rules:
    sql_injection: dict[str, re.Pattern[str]]
    directory_traversal: dict[str, re.Pattern[str]]
    brute_force: dict


def _compile_section(data: dict, section: str) -> dict[str, re.Pattern[str]]:
    items = data.get(section)
    if not isinstance(items, list) or not items:
        raise RulesError(f"'{section}' harus berupa daftar aturan, tidak boleh kosong")
    compiled: dict[str, re.Pattern[str]] = {}
    for i, item in enumerate(items, 1):
        if not isinstance(item, dict):
            raise RulesError(f"{section} #{i}: harus berupa pemetaan name/pattern")
        name, pattern = item.get("name"), item.get("pattern")
        if not isinstance(name, str) or not isinstance(pattern, str):
            raise RulesError(f"{section} #{i}: 'name' dan 'pattern' wajib berupa teks")
        if name in compiled:
            raise RulesError(f"{section}: nama ganda '{name}'")
        try:
            compiled[name] = re.compile(pattern)
        except re.error as exc:
            raise RulesError(f"{section} '{name}': regex rusak: {exc}") from exc
    return compiled


def _check_brute_force(cfg: object) -> dict:
    if not isinstance(cfg, dict):
        raise RulesError("'brute_force' harus berupa pemetaan")
    unknown = set(cfg) - BRUTE_FORCE_KEYS
    if unknown:
        raise RulesError(f"brute_force: kunci tidak dikenal: {sorted(unknown)}")
    for key in ("threshold", "window_seconds"):
        if key in cfg and (type(cfg[key]) is not int or cfg[key] < 1):
            raise RulesError(f"brute_force.{key} harus bilangan bulat >= 1")
    for key, kind in (("login_paths", str), ("statuses", int)):
        if key not in cfg:
            continue
        value = cfg[key]
        ok = isinstance(value, list) and value and all(type(v) is kind for v in value)
        if not ok:
            raise RulesError(
                f"brute_force.{key} harus daftar {kind.__name__}, tidak boleh kosong"
            )
        cfg[key] = tuple(value)
    return cfg


def load_rules(path: Path | str = DEFAULT_RULES_PATH) -> Rules:
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RulesError(f"YAML rusak di {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RulesError(f"{path}: tingkat atas harus berupa pemetaan")
    return Rules(
        sql_injection=_compile_section(data, "sql_injection"),
        directory_traversal=_compile_section(data, "directory_traversal"),
        brute_force=_check_brute_force(data.get("brute_force", {})),
    )


@cache
def default_rules() -> Rules:
    """Muat rules.yaml bawaan sekali saja."""
    return load_rules()
