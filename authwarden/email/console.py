"""Console email backend — prints to stdout instead of sending.

Use this during development and in tests. Switch to a real backend
in production by changing ``email_backend`` in WardenConfig.
"""
from __future__ import annotations

import sys
from typing import TextIO

from authwarden.email.base import EmailMessage


class ConsoleEmailBackend:
  """Renders email content to a stream (stdout by default).

  Satisfies AbstractEmailBackend via structural subtyping.

  Usage::

      backend = ConsoleEmailBackend()
      # or capture output in tests:
      import io
      stream = io.StringIO()
      backend = ConsoleEmailBackend(stream=stream)
      await backend.send(message)
      output = stream.getvalue()
  """

  def __init__(self, stream: TextIO | None = None) -> None:
    """Initialize the console backend.

    Args:
        stream: Output stream. Defeault to ``sys.stdout``.
    """
    self._stream = stream or sys.stdout

  async def send(self, message: EmailMessage) -> None:
    """Print the email to the configured stream.

    Args:
        message: The email to render.
    """
    border = "=" * 60
    lines = [
      f"\n{border}",
      f"TO:        {message.to}",
      f"SUBJECT:   {message.subject}",
      border,
      message.plain_text,
      f"{border}\n",
    ]
    print("\n".join(lines), file=self._stream)