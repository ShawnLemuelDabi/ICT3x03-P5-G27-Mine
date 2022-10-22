import os
from flask_mail import Mail, Message


def send_mail(app_context: any, subject: str, recipients: list[str], email_body: str) -> None:
    mail = Mail(app_context)

    msg = Message()
    msg.subject = subject
    msg.recipients = recipients
    msg.sender = os.environ.get("SMTP_USERNAME")
    msg.html = email_body

    mail.send(msg)
