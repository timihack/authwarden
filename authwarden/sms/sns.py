"""AWS SNS SMS backend for authwarden.

Requires boto3 (sync, run via asyncio.to_thread)::

    pip install boto3
"""
from __future__ import annotations
import asyncio
from authwarden.sms.base import SmsMessage

try:
    import boto3
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False


class AWSSNSSmsBackend:
    """Delivers SMS via AWS Simple Notification Service.

    Usage::

        backend = AWSSNSSmsBackend(region="us-east-1", sender_id="MyApp")

    AWS credentials are resolved from the environment (``AWS_ACCESS_KEY_ID``,
    ``AWS_SECRET_ACCESS_KEY``) or instance profile — standard boto3 chain.

    Raises:
        ImportError: At instantiation if boto3 is not installed.
    """

    def __init__(self, region: str = "us-east-1", sender_id: str | None = None) -> None:
        if not _BOTO3_AVAILABLE:
            raise ImportError("AWSSNSSmsBackend requires boto3: pip install boto3")
        self._region = region
        self._sender_id = sender_id

    async def send(self, message: SmsMessage) -> None:
        """Send an SMS via AWS SNS (runs boto3 call in a thread pool)."""
        await asyncio.to_thread(self._send_sync, message)

    def _send_sync(self, message: SmsMessage) -> None:
        client = boto3.client("sns", region_name=self._region)
        attrs: dict = {"SMSType": {"DataType": "String", "StringValue": "Transactional"}}
        if self._sender_id:
            attrs["SenderID"] = {"DataType": "String", "StringValue": self._sender_id}
        client.publish(PhoneNumber=message.to, Message=message.body, MessageAttributes=attrs)