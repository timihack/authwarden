# SMS Backends

## Built-in backends

| Backend | Use case | Extra dependency |
|---|---|---|
| `ConsoleSmsBackend` | Development — prints to stdout | none |
| `TwilioSmsBackend` | Twilio | none (uses `httpx`) |
| `AWSSNSSmsBackend` | AWS SNS | `boto3` — install via `pip install "authwarden[sns]"` |

Unlike email, there's **no `sms_backend` config selector field** — only credential fields (`twilio_account_sid`, etc.) exist on `WardenConfig`. You always build and pass the SMS backend instance directly.

## Twilio

```python
from authwarden.sms.twilio import TwilioSmsBackend

warden = AuthWarden(
    config=config,
    user_store=store,
    sms_backend=TwilioSmsBackend(
        account_sid="ACxxxx",
        auth_token="xxxx",
        from_number="+12025551234",
    ),
)
```

## AWS SNS

```python
from authwarden.sms.sns import AWSSNSSmsBackend

warden = AuthWarden(
    config=config,
    user_store=store,
    sms_backend=AWSSNSSmsBackend(region="us-east-1", sender_id="MyApp"),
)
```

AWS credentials resolve from the environment or instance profile — the standard boto3 credential chain, nothing authwarden-specific.

## Writing your own backend

```python
from authwarden.sms.base import SmsMessage

class MyProvider:
    async def send(self, message: SmsMessage) -> None:
        await my_sms_client.send(to=message.to, body=message.body)

warden = AuthWarden(config=config, user_store=store, sms_backend=MyProvider())
```

## Enabling SMS for verification/reset

The backend alone isn't enough — also tell `WardenConfig` to actually use it as a channel:

```python
config = WardenConfig(
    secret_key="...",
    verification_method="otp",               # SMS links don't make sense — OTP only
    verification_channels=["sms"],            # or ["email", "sms"] for both
    password_reset_method="otp",
    password_reset_channels=["sms"],
)
```

A user without a `phone_number` on file simply doesn't receive the SMS — `NotificationService` skips channels the user has no contact info for, rather than erroring.

## Overriding SMS copy

```python
from authwarden.sms.templates import SmsTemplates

class MySmsTemplates(SmsTemplates):
    def verify_otp(self, user, otp, expires_minutes):
        return f"[MyApp] Your code: {otp}. Valid {expires_minutes} min."

warden = AuthWarden(config=config, user_store=store, sms_templates=MySmsTemplates())
```
