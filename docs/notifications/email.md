# Email Backends

## Built-in backends

| Backend | Use case | Extra dependency |
|---|---|---|
| `ConsoleEmailBackend` | Development — prints to stdout | none |
| `SmtpEmailBackend` | Any SMTP server | none (uses `aiosmtplib`, already a core dep) |
| `SendGridEmailBackend` | SendGrid API | none (uses `httpx`, already a core dep) |
| `MailgunEmailBackend` | Mailgun API | none (uses `httpx`, already a core dep) |

`console` and `smtp` are auto-selectable via `WardenConfig.email_backend`. SendGrid and Mailgun aren't — build the instance and pass it to `AuthWarden` directly.

## Console (default)

```python
config = WardenConfig(secret_key="...", email_backend="console")
```
Prints every email to stdout — no setup, useful for local development.

## SMTP

```python
config = WardenConfig(
    secret_key="...",
    email_backend="smtp",
    smtp_host="smtp.gmail.com",
    smtp_port=587,
    smtp_username="you@gmail.com",
    smtp_password="app-password",
    emails_from_address="you@gmail.com",
    emails_from_name="My App",
)
```

## SendGrid

```python
from authwarden.email.sendgrid import SendGridEmailBackend

warden = AuthWarden(
    config=config,
    user_store=store,
    email_backend=SendGridEmailBackend(
        api_key="SG.xxxx",
        from_address="noreply@yourapp.com",
        from_name="My App",
    ),
)
```

## Mailgun

```python
from authwarden.email.mailgun import MailgunEmailBackend

warden = AuthWarden(
    config=config,
    user_store=store,
    email_backend=MailgunEmailBackend(
        api_key="key-xxxx",
        domain="mg.yourapp.com",
        from_address="noreply@mg.yourapp.com",
    ),
)
```

## Writing your own backend

Any object with this one method satisfies `AbstractEmailBackend` — no inheritance needed:

```python
from authwarden.email.base import EmailMessage

class PostmarkEmailBackend:
    def __init__(self, api_key: str):
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

warden = AuthWarden(config=config, user_store=store, email_backend=PostmarkEmailBackend(api_key="..."))
```

## Overriding email copy

```python
from authwarden.email.templates import EmailTemplates

class MyTemplates(EmailTemplates):
    def verify_email(self, user, link):
        return (
            "Welcome — confirm your email",
            f"Hi {user.full_name or 'there'},\n\nClick here: {link}",
            f"<h1>Welcome!</h1><a href='{link}'>Confirm email</a>",
        )

warden = AuthWarden(config=config, user_store=store, email_templates=MyTemplates())
```

Override any subset of methods — unoverridden ones fall back to the defaults. Full method list: `verify_email`, `verify_otp`, `welcome`, `password_reset`, `password_reset_otp`, `password_changed`, `mfa_enabled`, `mfa_disabled`.
