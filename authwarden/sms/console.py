"""Console SMS backend — prints to stdout. For development only."""
from __future__ import annotations
import sys
from typing import TextIO
from authwarden.sms.base import SmsMessage


class ConsoleSmsBackend:
    """Prints SMS to a stream instead of sending. Satisfies AbstractSmsBackend."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    async def send(self, message: SmsMessage) -> None:
        border = "-" * 40
        print(f"\n{border}", file=self._stream)
        print(f"SMS TO: {message.to}", file=self._stream)
        print(border, file=self._stream)
        print(message.body, file=self._stream)
        print(f"{border}\n", file=self._stream)