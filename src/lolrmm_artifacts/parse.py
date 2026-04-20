"""YAML -> Tool model with tolerant error handling."""

from __future__ import annotations

from dataclasses import dataclass

import yaml
from pydantic import ValidationError

from .fetch import FetchedFile
from .models import Tool


@dataclass
class ParseResult:
    tools: list[Tool]
    errors: list[tuple[str, str]]  # (filename, message)


def parse_many(files: list[FetchedFile]) -> ParseResult:
    tools: list[Tool] = []
    errors: list[tuple[str, str]] = []
    for f in files:
        try:
            raw = yaml.safe_load(f.content)
            if not isinstance(raw, dict):
                errors.append((f.name, "top-level is not a mapping"))
                continue
            tool = Tool.model_validate(raw)
            tool.source_file = f.name
            tools.append(tool)
        except (yaml.YAMLError, ValidationError) as e:
            errors.append((f.name, str(e).splitlines()[0][:200]))
        except Exception as e:  # noqa: BLE001 — surface unexpected parse bugs in `errors`
            errors.append((f.name, f"{type(e).__name__}: {e}"))
    return ParseResult(tools=tools, errors=errors)
