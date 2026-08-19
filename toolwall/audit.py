import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any, TextIO

from .types import normalize_arg_key


class AuditLog:
    """Append decision records as JSON Lines or retain them in memory."""

    def __init__(
        self,
        path: str | Path | None = None,
        redact: Iterable[str] = (),
    ) -> None:
        self.records: list[dict[str, Any]] = []
        self._redact = {normalize_arg_key(key) for key in redact}
        self._file: TextIO | None = (
            Path(path).open("a", encoding="utf-8") if path is not None else None
        )

    def _redacted(self, value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: (
                    "<redacted>"
                    if isinstance(key, str)
                    and normalize_arg_key(key) in self._redact
                    else self._redacted(item)
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._redacted(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redacted(item) for item in value)
        return value

    def write(self, record: dict[str, Any]) -> None:
        prepared = dict(record)
        prepared["args"] = self._redacted(prepared["args"])
        line = json.dumps(prepared, default=repr)
        prepared = json.loads(line)
        if self._file is None:
            self.records.append(prepared)
            return
        self._file.write(line + "\n")
        self._file.flush()
