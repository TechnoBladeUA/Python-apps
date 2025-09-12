import smtplib
from email.mime.text import MIMEText

def send_mail(sender, recipient, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender
    msg['To'] = recipient

    with smtplib.SMTP('localhost') as server:
        server.sendmail(sender, [recipient], msg.as_string())

if __name__ == "__main__":
    print("MailPython: Simple mail sender initialized.")