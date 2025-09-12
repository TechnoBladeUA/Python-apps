#!/usr/bin/env python3
import smtplib
from email.mime.text import MIMEText
import configparser
import os

def load_config():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "..", "config", "settings.ini"))
    return config

def send_mail(sender, recipient, subject, body):
    config = load_config()
    smtp_server = config.get("mail", "smtp_server", fallback="localhost")
    smtp_port = config.getint("mail", "smtp_port", fallback=25)

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.sendmail(sender, [recipient], msg.as_string())

if __name__ == "__main__":
    print("MailPython: Simple mail sender initialized.")
    # Example usage
    send_mail("admin@example.com", "test@example.com", "Hello", "This is a test email.")
