"""SendGrid email backend for authwarden.
 
Requires the ``httpx`` package::
 
    pip install httpx
 
No official SendGrid SDK dependency — uses the REST API directly,
keeping the dependency footprint small.
"""
from __future__ import annotations
 
from authwarden.email.base import EmailMessage
 
try:
    import httpx
    _HTTPX_AVAILABLE = True
except ImportError:
    _HTTPX_AVAILABLE = False
 
_SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"
 

class SendGridEmailBackend:
    """Delivers email via the SendGrid v3 Mail Send API.
 
    Satisfies AbstractEmailBackend via structural subtyping.
 
    Requirements::
 
        pip install httpx
 
    Usage::
 
        backend = SendGridEmailBackend(
            api_key="SG.xxxx",
            from_address="noreply@myapp.com",
            from_name="My App",
        )
 
    Raises:
        ImportError: At instantiation if httpx is not installed.
    """

    def __init__(
        self,
        api_key: str,
        from_address: str,
        from_name: str = "Authwarden",
    ) -> None:
        """Initialize the SendGrid backend.
        
        Args:
            api_key:      Your SendGrid API key (starting with "SG.").
            from_address: The email address to use in the "From" field (must be a verified in sendgrid).
            from_name:    The name to use in the "From" field (default: "Authwarden").

        Raises:
            ImportError: If httpx is not installed.
        """
        if not _HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required to use SendGridEmailBackend. "
                "Install it with: pip install httpx"
            )
        self.api_key = api_key
        self._from_address = from_address
        self._from_name = from_name
    
    async def send(self, message: EmailMessage) -> None:
        """Send an email message via SendGrid.
        
        Args:
            message: An EmailMessage instance containing the email details.

        Raises:
            httpx.HTTPError: If the HTTP request to SendGrid fails.
        """
        sender = message.from_address or self._from_address
        payload = {
            "personalizations": [{"to": [{"email": recipient} for recipient in message.to]}],
            "from": {"email": sender, "name": self._from_name},
            "subject": message.subject,
            "content": [
                {"type": "text/plain", "value": message.plain_text},
                {"type": "text/html", "value": message.html},
            ],
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient() as client:
            response = await client.post(_SENDGRID_API_URL, json=payload, headers=headers)
            response.raise_for_status()

