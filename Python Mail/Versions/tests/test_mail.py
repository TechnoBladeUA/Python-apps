import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "bin"))
from mail import send_mail

def test_send_mail():
    try:
        send_mail("test@example.com", "receiver@example.com", "Test", "Hello World")
        print("Test passed: send_mail executed successfully.")
    except Exception as e:
        print("Test failed:", e)

if __name__ == "__main__":
    test_send_mail()
