#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, scrolledtext
import smtplib
from email.mime.text import MIMEText
import configparser
import os

def load_config():
    config = configparser.ConfigParser()
    config.read(os.path.join(os.path.dirname(__file__), "..", "config", "settings.ini"))
    return config

def send_mail():
    sender = entry_from.get()
    recipient = entry_to.get()
    subject = entry_subject.get()
    body = text_body.get("1.0", tk.END).strip()

    if not sender or not recipient or not subject or not body:
        messagebox.showerror("Error", "All fields are required!")
        return

    config = load_config()
    smtp_server = config.get("mail", "smtp_server", fallback="localhost")
    smtp_port = config.getint("mail", "smtp_port", fallback=25)

    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = sender
        msg['To'] = recipient

        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.sendmail(sender, [recipient], msg.as_string())

        messagebox.showinfo("Success", "Email sent successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to send email: {e}")

# GUI setup
root = tk.Tk()
root.title("MailPython GUI")
root.geometry("500x400")

tk.Label(root, text="From:").pack(anchor="w", padx=10, pady=2)
entry_from = tk.Entry(root, width=60)
entry_from.pack(padx=10)

tk.Label(root, text="To:").pack(anchor="w", padx=10, pady=2)
entry_to = tk.Entry(root, width=60)
entry_to.pack(padx=10)

tk.Label(root, text="Subject:").pack(anchor="w", padx=10, pady=2)
entry_subject = tk.Entry(root, width=60)
entry_subject.pack(padx=10)

tk.Label(root, text="Body:").pack(anchor="w", padx=10, pady=2)
text_body = scrolledtext.ScrolledText(root, width=60, height=10)
text_body.pack(padx=10, pady=5)

send_button = tk.Button(root, text="Send Email", command=send_mail)
send_button.pack(pady=10)

root.mainloop()
