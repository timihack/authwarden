"""Abstract SMS backend and message model for authwarden.

Implement AbstractSmsBackend to plug in any SMS provider::

    class MyProvider:
        async def send(self, message: SmsMessage) -> None:
            await my_client.send(to=message.to, body=message.body)

Built-in backends: ConsoleSmsBackend, TwilioSmsBackend, AWSSNSSmsBackend.
"""
from __future__ import annotations
from pydantic import BaseModel
from typing import Protocol, runtime_checkable


class SmsMessage(BaseModel):
    """A single SMS message ready for delivery.

    Attributes:
        to:   Recipient phone number in E.164 format (e.g. ``+2348012345678``).
        body: Message text body (keep under 160 chars for single segment).
    """
    to: str
    body: str


@runtime_checkable
class AbstractSmsBackend(Protocol):
    """Protocol for SMS delivery backends.

    Any object with ``async send(message: SmsMessage) -> None`` satisfies this.
    """
    async def send(self, message: SmsMessage) -> None:
        """Deliver an SMS message.

        Args:
            message: The message to send.

        Raises:
            Exception: Any delivery failure.
        """
        ...