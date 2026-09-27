import sqlite3

def get_user_profile(user_id):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Vulnerability: Direct SQL Injection
    query = "SELECT username, email, is_admin FROM users WHERE id = '" + user_id + "'"
    cursor.execute(query)
    record = cursor.fetchone()
    conn.close()
    return record