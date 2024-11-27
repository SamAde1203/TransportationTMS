import sqlite3
import os

# Define the path to your SQLite database
DB_PATH = os.path.join(os.getcwd(), "fleetflow.db")

# Query to insert an admin user
def create_admin_user():
    query = """
    INSERT INTO users (username, password, role)
    VALUES (?, ?, ?)
    """
    hashed_password = "d2d65b870f312338b8daa507fb3032311eb365ee8f4e24ae7fc2c243cb3c305e"
    username = "Sammy"
    role = "Admin"

    # Connect to the database and execute the query
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query, (username, hashed_password, role))
        conn.commit()
        print(f"Admin user '{username}' created successfully.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    finally:
        conn.close()

# Run the function
if __name__ == "__main__":
    create_admin_user()
