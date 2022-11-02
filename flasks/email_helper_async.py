import os
from flask import copy_current_request_context
from flask_mail import Message, Mail
import threading


def send_mail_async(app_context: any, subject: str, recipients: list[str], email_body: str) -> None:
    # Reference: https://stackoverflow.com/questions/11047307/run-flask-mail-asynchronously
    mail = Mail(app_context)

    msg = Message()
    msg.subject = subject
    msg.recipients = recipients
    msg.sender = os.environ.get("SMTP_USERNAME")
    msg.html = email_body

    @copy_current_request_context
    def send_message(msg):
        mail.send(msg)

    sender = threading.Thread(name='email_helper_async.py', target=send_message, args=(msg,))
    sender.start()
