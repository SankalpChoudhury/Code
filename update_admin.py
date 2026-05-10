import sqlite3
from werkzeug.security import generate_password_hash

def update_admin():
    new_username = input("Enter new Admin ID (Username): ").strip()
    new_password = input("Enter new Admin Password: ").strip()

    if not new_username or not new_password:
        print("Error: Username and Password cannot be empty.")
        return

    hashed_password = generate_password_hash(new_password)

    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    try:
        # Check if the 'admin' user exists or if we need to update a specific user
        # We will set the role to 'admin' for this new username specifically
        
        # First, remove old admin role from anyone else (optional but safer)
        cursor.execute("UPDATE users SET role = 'user' WHERE role = 'admin'")
        
        # Check if new username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (new_username,))
        user = cursor.fetchone()

        if user:
            # Update existing user to admin with new password
            cursor.execute("UPDATE users SET password = ?, role = 'admin' WHERE username = ?", 
                           (hashed_password, new_username))
            print(f"Success: Existing user '{new_username}' has been promoted to Admin and password updated.")
        else:
            # Create new admin user
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", 
                           (new_username, hashed_password))
            print(f"Success: New Admin account '{new_username}' has been created.")

        conn.commit()
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    update_admin()
