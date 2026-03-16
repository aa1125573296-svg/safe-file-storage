import sqlite3
import os

def reset():
    db_path = "database.db"
    if os.path.exists(db_path):
        os.remove(db_path)
        print("Old DataBase deleted.")
    
if __name__ == "__main__":
    reset()