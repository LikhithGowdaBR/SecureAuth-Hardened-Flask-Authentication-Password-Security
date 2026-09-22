# Secure Flask Authentication

A compact Flask authentication app with bcrypt password hashing, CSRF protection,
login throttling, and a secure email reset-code flow.

## Run locally

```powershell
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe run.py
```

Open http://127.0.0.1:5000.

## Configuration

Copy `.env.example` to `.env` and set a unique `SECRET_KEY`. For production also
set `APP_ENV=production`; the app refuses to start if the key is empty or a known
example value. Configure `ADMIN_EMAIL` and `ADMIN_SMTP_PASSWORD` to enable reset
emails. Email remains disabled locally when these values are placeholders.

## Password protection

- Passwords use bcrypt with 13 rounds; plaintext passwords are never stored.
- The local risk classifier rejects common, personal, short, repetitive, and
  predictable passwords, and requires a strong 12+ character password.
- Reset codes are six-digit, cryptographically random, HMAC-protected in memory,
  expire after 10 minutes, and can be used only once.
- Forms use CSRF tokens; session cookies are HTTP-only and secure when production
  mode is enabled.

For multi-process production deployments, replace the in-memory reset-code and
login-throttle stores with Redis or a database.
