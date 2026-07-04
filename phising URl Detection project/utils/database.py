import sqlite3

conn = sqlite3.connect('users.db')

cursor = conn.cursor()

# Users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
''')

# Scan history table
cursor.execute('''
CREATE TABLE IF NOT EXISTS history(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    url TEXT,
    result TEXT,
    risk INTEGER
)
''')

conn.commit()

conn.close()

print("Database Ready")