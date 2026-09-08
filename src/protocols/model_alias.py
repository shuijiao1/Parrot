"""Same-protocol Chat response view: rewrite only its standard model metadata."""
from __future__ import annotations

import json
from typing import Iterator

from .sse import split_sse_events


def chat_response(obj: dict, model: str) -> dict:
    if isinstance(obj, dict) and isinstance(obj.get("choices"), list) and not obj.get("error"):
        return {**obj, "model": model}
    return obj


class ChatModelAliasStream:
    def __init__(self, model: str):
        self.model = model
        self.buffer = b""

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self.buffer += chunk
        self.buffer, events = split_sse_events(self.buffer)
        for event in events:
            lines = event.splitlines()
            data = b"\n".join(line[5:].lstrip(b" ") for line in lines if line.startswith(b"data:"))
            try:
                obj = json.loads(data)
            except (ValueError, UnicodeError):
                yield event + b"\n\n"  # Includes heartbeats, errors and [DONE].
                continue
            rewritten = chat_response(obj, self.model)
            if rewritten is obj:
                yield event + b"\n\n"
                continue
            encoded = b"data: " + json.dumps(rewritten, ensure_ascii=False, separators=(",", ":")).encode()
            output = []
            emitted = False
            for line in lines:
                if line.startswith(b"data:"):
                    if not emitted:
                        output.append(encoded)
                        emitted = True
                else:
                    output.append(line)
            yield b"\n".join(output) + b"\n\n"

    def close(self) -> Iterator[bytes]:
        # Do not manufacture a terminal event or alter an incomplete/error tail.
        if self.buffer:
            yield self.buffer
            self.buffer = b""
