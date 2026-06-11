"""Twilio SMS backend for authwarden.

Uses the Twilio Messages REST API directly via httpx.
No official Twilio SDK required — keeps the dependency footprint small.

Requires::

    pip install httpx
"""
from __future__ import annotations
from authwarden.sms.base import SmsMessage

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class TwilioSmsBackend:
    """Delivers SMS via the Twilio Messages API.

    Usage::

        backend = TwilioSmsBackend(
            account_sid="ACxxxxxxxx",
            auth_token="xxxxxxxx",
            from_number="+12025551234",
        )

    Raises:
        ImportError: At instantiation if httpx is not installed.
    """

    def __init__(self, account_sid: str, auth_token: str, from_number: str) -> None:
        if not _HTTPX_AVAILABLE:
            raise ImportError("TwilioSmsBackend requires httpx: pip install httpx")
        self._account_sid = account_sid
        self._auth_token = auth_token
        self._from_number = from_number
        self._api_url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"

    async def send(self, message: SmsMessage) -> None:
        """Send an SMS via Twilio.

        Raises:
            httpx.HTTPStatusError: On non-2xx Twilio response.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self._api_url,
                auth=(self._account_sid, self._auth_token),
                data={"From": self._from_number, "To": message.to, "Body": message.body},
            )
            resp.raise_for_status()