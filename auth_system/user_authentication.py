import sqlite3
from tkinter import *
from tkinter import messagebox, Toplevel
from ttkbootstrap import Window, ttk
from ttkbootstrap.constants import *
from database.tms_database import execute_query, hash_password


class UserAuthentication:
    def __init__(self, root):
        """Initializes the login/signup window."""
        self.root = root  # Expecting a ttkbootstrap.Window instance
        self.root.title("FleetFlow TMS - User Authentication")
        self.root.geometry("450x400")
        self.root.resizable(False, False)

        # Add an optional app icon (if exists)
        try:
            self.root.iconbitmap("assets/login_icon.ico")
        except FileNotFoundError:
            print("Icon not found, skipping.")

        # Initialize variables
        self.username = StringVar()
        self.password = StringVar()
        self.is_authenticated = False
        self.user_role = None

        # Create UI components
        self.create_login_ui()

    def create_login_ui(self):
        """Creates the login UI with a visually appealing design."""
        frame = ttk.Frame(self.root, padding=20, bootstyle="secondary")
        frame.pack(fill=BOTH, expand=True)

        # Title
        ttk.Label(
            frame,
            text="FleetFlow TMS Login",
            font=("Helvetica", 22, "bold"),
            bootstyle="inverse-primary"
        ).pack(pady=(20, 10), anchor=CENTER)

        ttk.Label(
            frame,
            text="Welcome to FleetFlow TMS. Please log in to continue.",
            font=("Arial", 11),
            bootstyle="secondary"
        ).pack(anchor=CENTER, pady=5)

        # Username field
        ttk.Label(frame, text="Username", font=("Arial", 12, "bold")).pack(anchor=W, pady=(10, 5))
        ttk.Entry(frame, textvariable=self.username, font=("Arial", 12)).pack(fill=X, pady=(0, 15))

        # Password field
        ttk.Label(frame, text="Password", font=("Arial", 12, "bold")).pack(anchor=W, pady=(5, 5))
        ttk.Entry(frame, textvariable=self.password, show="*", font=("Arial", 12)).pack(fill=X, pady=(0, 15))

        # Login Button
        ttk.Button(
            frame, text="Login", bootstyle="success", command=self.authenticate_user
        ).pack(fill=X, pady=(15, 5))

        # Sign Up Button
        ttk.Button(
            frame, text="Sign Up", bootstyle="primary-outline", command=self.create_signup_ui
        ).pack(fill=X, pady=5)

        # Exit Button
        ttk.Button(
            frame, text="Exit", bootstyle="danger", command=self.exit_app
        ).pack(fill=X, pady=(5, 10))

    def authenticate_user(self):
        """Authenticates the user."""
        username = self.username.get().strip()
        password = self.password.get().strip()
        hashed_password = hash_password(password)

        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        user = execute_query(query, (username, hashed_password), fetch=True)

        if user:
            self.is_authenticated = True
            self.user_role = user[0]['role']
            messagebox.showinfo("Success", f"Welcome {username} ({self.user_role})!")
            self.root.destroy()
        else:
            messagebox.showerror("Error", "Invalid username or password!")

    def create_signup_ui(self):
        """Opens the signup window."""
        signup_window = Toplevel(self.root)
        signup_window.title("Sign Up - FleetFlow TMS")
        signup_window.geometry("400x350")
        signup_window.resizable(False, False)

        # Attempt to set the window icon
        try:
            signup_window.iconbitmap("assets/signup_icon.ico")
        except FileNotFoundError:
            print("Signup icon not found, skipping.")

        # Variables for signup
        new_username = StringVar()
        new_password = StringVar()

        # Frame for signup UI
        signup_frame = ttk.Frame(signup_window, padding=20, bootstyle="secondary")
        signup_frame.pack(fill=BOTH, expand=True)

        ttk.Label(
            signup_frame,
            text="Create a New Account",
            font=("Helvetica", 18, "bold"),
            bootstyle="inverse-primary"
        ).pack(pady=(10, 10))

        # Username field
        ttk.Label(signup_frame, text="Username", font=("Arial", 12, "bold")).pack(anchor=W, pady=(10, 5))
        ttk.Entry(signup_frame, textvariable=new_username, font=("Arial", 12)).pack(fill=X, pady=(0, 10))

        # Password field
        ttk.Label(signup_frame, text="Password", font=("Arial", 12, "bold")).pack(anchor=W, pady=(5, 5))
        ttk.Entry(signup_frame, textvariable=new_password, show="*", font=("Arial", 12)).pack(fill=X, pady=(0, 15))

        # Save Button
        def register_user():
            username = new_username.get().strip()
            password = new_password.get().strip()

            if not username or not password:
                messagebox.showerror("Error", "Both fields are required!")
                return

            hashed_password = hash_password(password)

            try:
                query = "INSERT INTO users (username, password, role) VALUES (?, ?, 'User')"
                execute_query(query, (username, hashed_password))
                messagebox.showinfo("Success", "User registered successfully!")
                signup_window.destroy()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists!")

        ttk.Button(
            signup_frame, text="Sign Up", bootstyle="success", command=register_user
        ).pack(fill=X, pady=20)

        ttk.Button(
            signup_frame, text="Cancel", bootstyle="danger-outline", command=signup_window.destroy
        ).pack(fill=X, pady=(5, 10))

    def exit_app(self):
        """Closes the application."""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            self.root.destroy()


# Example of main app execution
if __name__ == "__main__":
    root = Window(themename="darkly")  # Using ttkbootstrap for modern UI
    app = UserAuthentication(root)
    root.mainloop()
