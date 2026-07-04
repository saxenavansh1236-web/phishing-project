"""
migrate_passwords.py  --  One-time migration script
Hashes all plain-text passwords already stored in users.db.

Run ONCE after deploying the werkzeug password-hashing fix:
    python migrate_passwords.py
"""

import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


HASH_PREFIXES = ("pbkdf2:", "scrypt:", "bcrypt:", "argon2:")

def already_hashed(password: str) -> bool:
    """Return True if the value looks like a werkzeug hash (safe to skip)."""
    return any(password.startswith(p) for p in HASH_PREFIXES)


def migrate(db_path: str = "users.db") -> None:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    users = conn.execute("SELECT id, username, password FROM users").fetchall()

    migrated = 0
    skipped  = 0

    for user in users:
        if already_hashed(user["password"]):
            print(f"  ⏭  Skipping '{user['username']}' — already hashed.")
            skipped += 1
        else:
            hashed = generate_password_hash(user["password"])
            conn.execute(
                "UPDATE users SET password = ? WHERE id = ?",
                (hashed, user["id"]),
            )
            print(f"  ✅ Hashed password for '{user['username']}'.")
            migrated += 1

    conn.commit()
    conn.close()

    print(f"\nDone. {migrated} migrated, {skipped} skipped.")


if __name__ == "__main__":
    migrate()