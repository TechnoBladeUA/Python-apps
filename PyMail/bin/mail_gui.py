#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from tkinter import filedialog
import smtplib, imaplib, email
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import decode_header, make_header
import configparser
import os, csv, datetime, traceback

from crypto_utils import ensure_key, encrypt_str, decrypt_str, get_key_path

APP_DIR = os.path.dirname(__file__)
ROOT_DIR = os.path.abspath(os.path.join(APP_DIR, ".."))
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "settings.ini")

def load_config():
    cfg = configparser.ConfigParser()
    cfg.read(CONFIG_PATH)
    # ensure sections/keys exist
    if "mail" not in cfg: cfg["mail"] = {}
    m = cfg["mail"]
    m.setdefault("smtp_server", "smtp.gmail.com")
    m.setdefault("smtp_port", "587")
    m.setdefault("smtp_use_tls", "true")
    m.setdefault("imap_server", "imap.gmail.com")
    m.setdefault("imap_port", "993")
    m.setdefault("email", "your_email@example.com")
    m.setdefault("password_encrypted", "")
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)
    return cfg

def save_config(cfg):
    with open(CONFIG_PATH, "w") as f:
        cfg.write(f)

def log_message(msg):
    logs_path = os.path.join(ROOT_DIR, "logs", "activity.log")
    with open(logs_path, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}\n")

def send_mail():
    sender = entry_from.get().strip()
    recipient = entry_to.get().strip()
    subject = entry_subject.get().strip()
    body = text_body.get("1.0", tk.END).rstrip()

    if not sender or not recipient or not subject or not body:
        messagebox.showerror("Error", "All fields are required.")
        return

    cfg = load_config()
    m = cfg["mail"]
    smtp_server = m.get("smtp_server", "smtp.gmail.com")
    smtp_port = int(m.get("smtp_port", "587"))
    use_tls = m.get("smtp_use_tls", "true").lower() == "true"
    email_addr = m.get("email", sender)
    enc_pwd = m.get("password_encrypted", "")

    try:
        pwd = decrypt_str(enc_pwd) if enc_pwd else ""
    except Exception:
        pwd = ""
    # Build message
    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain", "utf-8"))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
        if use_tls:
            server.starttls()
        if email_addr and pwd:
            server.login(email_addr, pwd)
        server.sendmail(sender, [recipient], msg.as_string())
        server.quit()

        # Save to outbox
        out_path = os.path.join(ROOT_DIR, "data", "outbox",
                                f"sent_{datetime.datetime.now():%Y%m%d_%H%M%S}.eml")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(msg.as_string())

        log_message(f"Sent email to {recipient} | Subject: {subject}")
        messagebox.showinfo("Success", "Email sent and saved to Outbox.")
    except Exception as e:
        log_message("Send failed: " + repr(e))
        messagebox.showerror("Send failed", f"{e}\n\n{traceback.format_exc()}")

def save_draft():
    draft_path = os.path.join(ROOT_DIR, "data", "drafts",
                              f"draft_{datetime.datetime.now():%Y%m%d_%H%M%S}.txt")
    with open(draft_path, "w", encoding="utf-8") as f:
        f.write(f"From: {entry_from.get()}\n")
        f.write(f"To: {entry_to.get()}\n")
        f.write(f"Subject: {entry_subject.get()}\n\n")
        f.write(text_body.get("1.0", tk.END))
    log_message("Draft saved: " + draft_path)
    messagebox.showinfo("Draft Saved", f"Draft saved to:\n{draft_path}")

def open_contacts():
    contacts_path = os.path.join(ROOT_DIR, "data", "contacts.csv")
    if not os.path.exists(contacts_path):
        messagebox.showwarning("Contacts", "No contacts found.")
        return
    win = tk.Toplevel(root)
    win.title("Contacts")
    win.geometry("360x280")
    frame = ttk.Frame(win, padding=10)
    frame.pack(fill="both", expand=True)
    lb = tk.Listbox(frame)
    lb.pack(side="left", fill="both", expand=True)
    sb = ttk.Scrollbar(frame, orient="vertical", command=lb.yview)
    sb.pack(side="right", fill="y")
    lb.config(yscrollcommand=sb.set)
    with open(contacts_path, newline='', encoding="utf-8") as csvfile:
        reader = csv.reader(csvfile)
        next(reader, None)
        for name, email_addr in reader:
            lb.insert("end", f"{name} <{email_addr}>")
    def on_select(evt):
        sel = lb.get(lb.curselection())
        if "<" in sel and ">" in sel:
            addr = sel.split("<",1)[1].split(">",1)[0]
            entry_to.delete(0, "end")
            entry_to.insert(0, addr)
            win.destroy()
    lb.bind("<Double-Button-1>", on_select)

def view_logs():
    logs_path = os.path.join(ROOT_DIR, "logs", "activity.log")
    win = tk.Toplevel(root)
    win.title("Logs")
    win.geometry("600x400")
    txt = scrolledtext.ScrolledText(win, wrap="word")
    txt.pack(fill="both", expand=True)
    if os.path.exists(logs_path):
        with open(logs_path, "r", encoding="utf-8") as f:
            txt.insert("1.0", f.read())
    txt.config(state="disabled")

def open_inbox():
    cfg = load_config(); m = cfg["mail"]
    imap_server = m.get("imap_server", "imap.gmail.com")
    imap_port = int(m.get("imap_port", "993"))
    email_addr = m.get("email", "")
    enc_pwd = m.get("password_encrypted", "")
    try:
        pwd = decrypt_str(enc_pwd) if enc_pwd else ""
    except Exception:
        pwd = ""
    win = tk.Toplevel(root); win.title("Inbox"); win.geometry("700x450")
    cols = ("From", "Subject", "Date")
    tree = ttk.Treeview(win, columns=cols, show="headings")
    for c in cols:
        tree.heading(c, text=c)
        tree.column(c, width=220 if c!="Date" else 140, anchor="w")
    tree.pack(fill="both", expand=True)
    status = ttk.Label(win, text="Connecting..."); status.pack(anchor="w", padx=6, pady=4)

    try:
        imap = imaplib.IMAP4_SSL(imap_server, imap_port)
        imap.login(email_addr, pwd)
        imap.select("INBOX")
        status.config(text="Fetching latest 50 emails...")
        typ, data = imap.search(None, "ALL")
        ids = data[0].split()
        ids = ids[-50:] if len(ids) > 50 else ids
        for msg_id in reversed(ids):
            typ, msg_data = imap.fetch(msg_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            frm = str(make_header(decode_header(msg.get("From", ""))))
            subj = str(make_header(decode_header(msg.get("Subject", ""))))
            date = msg.get("Date", "")
            tree.insert("", "end", values=(frm, subj, date), tags=(str(msg_id),))
        status.config(text="Double-click a row to view the message.")
        def on_open(evt):
            item = tree.selection()
            if not item: return
            # fetch again for full content
            mid = tree.item(item[0], "tags")[0]
            typ, msg_data = imap.fetch(mid, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            show_message(msg)
        tree.bind("<Double-Button-1>", on_open)
    except Exception as e:
        messagebox.showerror("Inbox Error", f"{e}\n\n{traceback.format_exc()}")
        log_message("Inbox error: " + repr(e))

def show_message(msg):
    win = tk.Toplevel(root); win.title("Message"); win.geometry("700x500")
    hdr = f"From: {msg.get('From','')}\nTo: {msg.get('To','')}\nSubject: {msg.get('Subject','')}\nDate: {msg.get('Date','')}\n\n"
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition"))
            if ctype == "text/plain" and "attachment" not in disp:
                body += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="replace")
                break
    else:
        body = msg.get_payload(decode=True)
        if isinstance(body, bytes):
            body = body.decode(msg.get_content_charset() or "utf-8", errors="replace")
    txt = scrolledtext.ScrolledText(win, wrap="word")
    txt.pack(fill="both", expand=True)
    txt.insert("1.0", hdr + body)
    txt.config(state="disabled")

def open_outbox():
    out_dir = os.path.join(ROOT_DIR, "data", "outbox")
    win = tk.Toplevel(root); win.title("Outbox"); win.geometry("700x450")
    lb = tk.Listbox(win)
    lb.pack(fill="both", expand=True)
    files = sorted([f for f in os.listdir(out_dir) if f.endswith(".eml")])
    for f in files: lb.insert("end", f)
    def open_selected(evt):
        sel = lb.get(lb.curselection())
        path = os.path.join(out_dir, sel)
        with open(path, "r", encoding="utf-8") as fp:
            raw = fp.read()
        # parse and show
        msg = email.message_from_string(raw)
        show_message(msg)
    lb.bind("<Double-Button-1>", open_selected)

def open_settings():
    ensure_key(os.path.join(ROOT_DIR, "config"))  # ensure key exists
    cfg = load_config(); m = cfg["mail"]

    win = tk.Toplevel(root); win.title("Settings"); win.geometry("420x360")
    frame = ttk.Frame(win, padding=10); frame.pack(fill="both", expand=True)

    # fields
    entries = {}
    def add_row(label, key, default=""):
        ttk.Label(frame, text=label).pack(anchor="w")
        e = ttk.Entry(frame, width=46)
        e.pack(pady=3, fill="x")
        e.insert(0, m.get(key, default))
        entries[key] = e

    add_row("SMTP server", "smtp_server", "smtp.gmail.com")
    add_row("SMTP port", "smtp_port", "587")
    add_row("Use STARTTLS (true/false)", "smtp_use_tls", "true")
    add_row("IMAP server", "imap_server", "imap.gmail.com")
    add_row("IMAP port", "imap_port", "993")
    add_row("Email (login)", "email", m.get("email",""))

    ttk.Label(frame, text="Password").pack(anchor="w")
    e_pwd = ttk.Entry(frame, width=46, show="•")
    # Try to display decrypted password
    try:
        dec = decrypt_str(m.get("password_encrypted",""))
    except Exception:
        dec = ""
    if dec: e_pwd.insert(0, dec)
    e_pwd.pack(pady=3, fill="x")

    def save():
        # write back
        for k, e in entries.items():
            m[k] = e.get().strip()
        # encrypt password
        pwd_plain = e_pwd.get()
        m["password_encrypted"] = encrypt_str(pwd_plain) if pwd_plain else ""
        save_config(cfg)
        messagebox.showinfo("Settings", "Settings saved.")
        win.destroy()

    ttk.Button(frame, text="Save", command=save).pack(pady=8, side="left")
    ttk.Button(frame, text="Cancel", command=win.destroy).pack(pady=8, side="right")

def about():
    messagebox.showinfo("About", "MailPython Client v4\nReal SMTP/IMAP + Encrypted password storage.")

# --- GUI ---
root = tk.Tk()
root.title("MailPython Client v4")
root.geometry("720x560")

# Menu
menubar = tk.Menu(root)
filemenu = tk.Menu(menubar, tearoff=0)
filemenu.add_command(label="Send", command=send_mail)
filemenu.add_command(label="Save Draft", command=save_draft)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=root.quit)
menubar.add_cascade(label="File", menu=filemenu)

toolsmenu = tk.Menu(menubar, tearoff=0)
toolsmenu.add_command(label="Inbox (IMAP)", command=open_inbox)
toolsmenu.add_command(label="Outbox", command=open_outbox)
toolsmenu.add_command(label="Contacts", command=open_contacts)
toolsmenu.add_command(label="Logs", command=view_logs)
toolsmenu.add_separator()
toolsmenu.add_command(label="Settings", command=open_settings)
menubar.add_cascade(label="Tools", menu=toolsmenu)

helpmenu = tk.Menu(menubar, tearoff=0)
helpmenu.add_command(label="About", command=about)
menubar.add_cascade(label="Help", menu=helpmenu)

root.config(menu=menubar)

# Layout
pad = {"padx": 10, "pady": 3}
ttk.Label(root, text="From:").pack(anchor="w", **pad)
entry_from = ttk.Entry(root, width=90); entry_from.pack(fill="x", **pad)
ttk.Label(root, text="To:").pack(anchor="w", **pad)
entry_to = ttk.Entry(root, width=90); entry_to.pack(fill="x", **pad)
ttk.Label(root, text="Subject:").pack(anchor="w", **pad)
entry_subject = ttk.Entry(root, width=90); entry_subject.pack(fill="x", **pad)
ttk.Label(root, text="Body:").pack(anchor="w", **pad)
text_body = scrolledtext.ScrolledText(root, width=90, height=16); text_body.pack(fill="both", expand=True, **pad)

# Preload config to populate From field
cfg0 = load_config()
entry_from.insert(0, cfg0["mail"].get("email",""))

root.mainloop()
