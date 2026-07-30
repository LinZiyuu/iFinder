"""Small helpers shared by the agents (JSON extraction from LLM replies)."""

from __future__ import annotations

import json
import re
from typing import Any

_FENCED = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> Any:
    """Best-effort extraction of a JSON value from an LLM reply.

    Tries, in order: a fenced ```json block, then the first balanced ``{...}`` or ``[...]`` span.
    Raises ``ValueError`` if nothing parses.
    """
    for candidate in _candidates(text):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    raise ValueError("no parseable JSON found in text")


def _candidates(text: str):
    for m in _FENCED.finditer(text):
        yield m.group(1).strip()
    # first balanced object / array
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        if start == -1:
            continue
        depth = 0
        for i in range(start, len(text)):
            c = text[i]
            if c == opener:
                depth += 1
            elif c == closer:
                depth -= 1
                if depth == 0:
                    yield text[start : i + 1]
                    break
    yield text.strip()
