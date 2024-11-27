from tkinter import Tk
from auth_system.user_authentication import UserAuthentication  # Import the login system
from gui.tms_gui import TransportManagementSystem  # Import the main application GUI
from database import tms_database  # Import the database functions


def main():
    """
    Entry point for the FleetFlow TMS application.
    """
    try:
        # Ensure all necessary tables are created
        tms_database.create_tables()
        print("Database tables created successfully.")
    except Exception as e:
        print(f"Error during database initialization: {e}")
        return

    # Step 1: Launch Login Window
    root = Tk()
    login = UserAuthentication(root)
    root.mainloop()

    # Step 2: Launch Main Application if login is successful
    if login.is_authenticated:
        app_root = Tk()
        app = TransportManagementSystem(app_root, username=login.username, user_role=login.user_role)
        app_root.mainloop()
    else:
        print("Authentication failed or canceled. Exiting application.")


if __name__ == '__main__':
    main()
