import sqlite3
import os

# --- VULNERABILITY 1: Hardcoded Secret ---
# SAST tools should flag credentials stored directly in source code.
DATABASE_PASSWORD = "super_secret_password_123"

def initialize_database():
    """Initializes a simple SQLite database."""
    conn = sqlite3.connect("experiment_data.db")
    cursor = conn.cursor()
    
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)"
    )
    cursor.execute(
        "INSERT INTO users (username, role) VALUES ('admin', 'superuser')"
    )
    conn.commit()
    conn.close()

def search_user(username_input):
    """
    VULNERABILITY 2: SQL Injection
    Uses string concatenation to build a SQL query, allowing an attacker to modify
    the query structure (e.g., ' or 1=1 --).
    """
    db_name = "experiment_data.db"
    
    print(f"Connecting to database: {db_name}")
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()

    # Vulnerable Query Construction
    query = f"SELECT role FROM users WHERE username = '{username_input}'"
    
    print(f"Executing query: {query}")
    try:
        cursor.execute(query) # The SAST tool will point to this line.
        result = cursor.fetchone()
        if result:
            print(f"User role found: {result[0]}")
        else:
            print("User not found.")
    except Exception as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    initialize_database()
    
    # Test cases:
    print("\n--- Testing valid search ---")
    search_user("admin")
    
    print("\n--- Testing SQL Injection payload (Should be flagged by SAST) ---")
    # This payload is meant to bypass authentication or extract data.
    sql_payload = "' OR 1=1 --" 
    search_user(sql_payload)
    
    # Check if the hardcoded secret is accessible (it is!)
    print(f"\nSecret credential check: {DATABASE_PASSWORD}")
    
