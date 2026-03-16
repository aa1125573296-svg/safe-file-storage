import sqlite3

def make_admin(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute("UPDATE users SET role = 'admin' WHERE username = ?", (username,))
    
    if cursor.rowcount > 0:
        print(f"Success! '{username}' is now an admin.")
    else:
        print(f"Error: User '{username}' not found.")
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    name = input("Enter the username to make admin: ")
    make_admin(name)