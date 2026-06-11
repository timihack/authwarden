"""SMTP email backend using aiosmtplib.
 
Works with any SMTP server: Gmail, Outlook, Mailhog (dev), custom relay, etc.
Configure via WardenConfig smtp_* fields or pass parameters directly.
"""
from __future__ import annotations

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from authwarden.core.config import WardenConfig
from authwarden.email.base import EmailMessage


class SmtpEmailBackend:
  """Sends email via SMTP using aiosmtplib.

  Satisfies AbstractEmailBackend via structural subtyping.

  Usage::

      # From WardenConfig (recommended)
      backend = SmtpEmailBackend.from_config(config)

      # Direct instantiation
      backend = SmtpEmailBackend(
          hostname="smtp.gmail.com",
          port=587,
          username="you@gmail.com",
          password="app-password",
          use_tls=True,
          from_address="you@gmail.com",
          from_name="My App",
      )
  """

  def __init__(
      self,
      hostname: str,
      port: int,
      from_address: str,
      from_name: str = "AuthWarden",
      username: str | None = None,
      password: str | None = None,
      use_tls: bool = True,
  ) -> None:
    self._hostname = hostname
    self._port = port
    self._username = username
    self._password = password
    self._use_tls = use_tls
    self._from_address = from_address
    self._from_name = from_name

  @classmethod
  def from_config(cls, config: WardenConfig) -> "SmtpEmailBackend":
    """Construct an SmtpEmailBackend from a WardenConfig instance.
 
    Args:
        config: The application WardenConfig.

    Returns:
        A configured SmtpEmailBackend.
    """
    return cls(
      hostname=config.smtp_host,
      port=config.smtp_port,
      username=config.smtp_username,
      password=config.smtp_password,
      use_tls=config.smtp_use_tls,
      from_address=config.emails_from_address,
      from_name=config.emails_from_name,
    )
  
  async def send(self, message: EmailMessage) -> None:
    """Build a MIME email and deliver it via SMTP.

    Args:
        message: The email to send.

    Raises:
        aiosmtplib.SMTPException: On SMTP-level delivery failures.
    """
    sender = message.from_address or self._from_address
    from_header = f"{self._from_name} <{sender}>"

    mime = MIMEMultipart("alternative")
    mime["From"]    = from_header
    mime["To"]      = message.to
    mime["Subject"] = message.subject
    mime.attach(MIMEText(message.plain_text, "plain", "utf-8"))
    mime.attach(MIMEText(message.html, "html", "utf-8"))

    await aiosmtplib.send(
      mime,
      hostname = self._hostname,
      port     = self._port,
      username = self._username,
      password = self._password,
      use_tls  = self._use_tls,
    )