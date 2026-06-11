"""Mailgun email backend for authwarden.

Requires the ``httpx`` package::

    pip install httpx

Uses the Mailgun Messages API directly — no official SDK required.
"""
from __future__ import annotations

from authwarden.email.base import EmailMessage

try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False


class MailgunEmailBackend:
    """Delivers email via the Mailgun Messages API.

    Satisfies AbstractEmailBackend via structural subtyping.

    Requirements::

        pip install httpx

    Usage::

        backend = MailgunEmailBackend(
            api_key="key-xxxx",
            domain="mg.myapp.com",
            from_address="noreply@mg.myapp.com",
            from_name="My App",
        )

    Raises:
        ImportError: At instantiation if httpx is not installed.
    """

    def __init__(
        self,
        api_key: str,
        domain: str,
        from_address: str,
        from_name: str = "AuthWarden",
        eu_region: bool = False,
    ) -> None:
        """Initialise the Mailgun backend.

        Args:
            api_key:      Mailgun private API key.
            domain:       Your sending domain (e.g. ``mg.myapp.com``).
            from_address: Sender address — must belong to the domain.
            from_name:    Sender display name.
            eu_region:    Set True to use the EU Mailgun endpoint.

        Raises:
            ImportError: If httpx is not installed.
        """
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "MailgunEmailBackend requires httpx. "
                "Install it with: pip install httpx"
            )
        self._api_key = api_key
        self._domain = domain
        self._from_address = from_address
        self._from_name = from_name
        base = "api.eu.mailgun.net" if eu_region else "api.mailgun.net"
        self._api_url = f"https://{base}/v3/{domain}/messages"

    async def send(self, message: EmailMessage) -> None:
        """Deliver an email via the Mailgun API.

        Args:
            message: The email to send.

        Raises:
            httpx.HTTPStatusError: If Mailgun returns a non-2xx response.
        """
        sender = message.from_address or self._from_address
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._api_url,
                auth=("api", self._api_key),
                data={
                    "from": f"{self._from_name} <{sender}>",
                    "to": message.to,
                    "subject": message.subject,
                    "text": message.plain_text,
                    "html": message.html,
                },
            )
            response.raise_for_status()
            