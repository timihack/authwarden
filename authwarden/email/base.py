"""Abstract email backend and message model for authwarden.

The AbstractEmailBackend protocol makes it trivial to plug in any email
service. Implement a single async ``send()`` method::

  class PostmarkEmailBackend:
      def __init__(self, api_key: str) -> None:
          self._api_key = api_key

      async def send(self, message: EmailMessage) -> None:
          async with httpx.AsyncClient() as client:
              await client.post(
                  "https://api.postmarkapp.com/email",
                  headers={"X-Postmark-Server-Token": self._api_key},
                  json={
                      "From": message.from_address,
                      "To": message.to,
                      "Subject": message.subject,
                      "TextBody": message.plain_text,
                      "HtmlBody": message.html,
                  },
              )

Built-in backends: ConsoleEmailBackend, SmtpEmailBackend,
                  SendGridEmailBackend, MailgunEmailBackend.
"""
from __future__ import annotations

from pydantic import BaseModel
from typing import Protocol, runtime_checkable


class EmailMessage(BaseModel):
  """A complete email message ready for delivery.

  Attributes:
      to:           Recipient email address.
      subject:      Email subject line.
      plain_text:   Plain-text body (required — always provide a fallback).
      html:         HTML body.
      from_address: Override the sender address for this specific message.
                    Falls back to the backend's configured from_address.
  """

  to: str
  subject: str
  plain_text: str
  html: str | None = None
  from_address: str | None = None  # override per-message if needed


@runtime_checkable
class AbstractEmailBackend(Protocol):
  """Protocol for email delivery backends.

  Any object with an async ``send(message: EmailMessage) -> None`` method
  satisfies this protocol — no inheritance required.

  Built-in implementations:

  - :class:`~authwarden.email.console.ConsoleEmailBackend` — prints to stdout
  - :class:`~authwarden.email.smtp.SmtpEmailBackend` — sends via SMTP
  - :class:`~authwarden.email.sendgrid.SendGridEmailBackend` — SendGrid API
  - :class:`~authwarden.email.mailgun.MailgunEmailBackend` — Mailgun API
  """

  async def send(self, message: EmailMessage) -> None:
    """Deliver an email message.

    Args:
        message: The fully constructed EmailMessage to send.

    Raises:
        Exception: Any delivery failure. Callers should catch and handle
                    (e.g. log the error, do not expose internals to users).
    """
    ...