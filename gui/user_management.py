import hashlib
import sqlite3
import tkinter
from tkinter import *
from tkinter import ttk, messagebox

from ttkbootstrap.dialogs import Messagebox

from database.tms_database import execute_query, hash_password

class UserManagement:
    def __init__(self, root):
        """Initializes the User Management window."""
        self.root = root
        self.root.title("User Management")
        self.root.geometry("800x600")

        # Apply styles
        self.apply_styles()

        # UI Components
        self.username = StringVar()
        self.password = StringVar()
        self.role = StringVar(value="User")  # Default role set to "User"

        self.initialize_ui()

    def apply_styles(self):
        """Apply styling to the widgets."""
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10), padding=5)
        style.configure("TLabel", font=("Helvetica", 12), padding=5)
        style.configure("TEntry", padding=5)
        style.configure("Treeview.Heading", font=("Helvetica", 12, "bold"))

    def initialize_ui(self):
        """Sets up the User Management UI."""
        # Title
        ttk.Label(self.root, text="User Management", font=("Helvetica", 16, "bold")).pack(pady=10)

        # Search and Filter
        self.create_search_bar()
        self.create_role_filter()

        # Form Section
        form_frame = ttk.Frame(self.root)
        form_frame.pack(fill=X, padx=20, pady=10)

        self.create_label_and_entry("Username", self.username, parent=form_frame)
        self.create_label_and_entry("Password", self.password, show="*", parent=form_frame)
        ttk.Label(form_frame, text="Role").pack(anchor=W, pady=5)
        ttk.Combobox(form_frame, textvariable=self.role, values=["Admin", "User"], state="readonly").pack(fill=X)

        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(fill=X, pady=10)

        ttk.Button(button_frame, text="Add User", command=self.add_user).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Update User", command=self.update_user).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Delete User", command=self.delete_user).pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Reset Password", command=self.reset_password).pack(side=LEFT, padx=5)

        # User List
        self.user_list = ttk.Treeview(self.root, columns=("Username", "Role"), show="headings", height=10)
        self.user_list.heading("Username", text="Username")
        self.user_list.heading("Role", text="Role")
        self.user_list.pack(fill=BOTH, expand=True, pady=10)
        self.user_list.bind("<<TreeviewSelect>>", self.on_user_select)

        self.load_users()

    def create_label_and_entry(self, label, variable, show=None, parent=None):
        """Creates a label and entry pair."""
        if not parent:
            parent = self.root
        ttk.Label(parent, text=label).pack(anchor=W, padx=20, pady=5)
        ttk.Entry(parent, textvariable=variable, show=show).pack(fill=X, padx=20)

    def create_search_bar(self):
        """Creates a search bar to find users."""
        search_frame = ttk.Frame(self.root)
        search_frame.pack(fill=X, padx=20, pady=5)

        self.search_query = StringVar()
        ttk.Label(search_frame, text="Search User:").pack(side=LEFT)
        ttk.Entry(search_frame, textvariable=self.search_query).pack(side=LEFT, fill=X, expand=True, padx=10)
        ttk.Button(search_frame, text="Search", command=self.search_user).pack(side=LEFT)

    def create_role_filter(self):
        """Adds a dropdown to filter users by role."""
        self.filter_role = StringVar(value="All")
        filter_frame = ttk.Frame(self.root)
        filter_frame.pack(fill=X, padx=20, pady=5)

        ttk.Label(filter_frame, text="Filter by Role:").pack(side=LEFT)
        ttk.Combobox(filter_frame, textvariable=self.filter_role, values=["All", "Admin", "User"], state="readonly").pack(side=LEFT, padx=10)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_role_filter).pack(side=LEFT)

    def load_users(self):
        """Loads users into the list."""
        self.user_list.delete(*self.user_list.get_children())
        users = execute_query("SELECT username, role FROM users", fetch=True)
        for user in users:
            self.user_list.insert("", END, values=(user["username"], user["role"]))

    def on_user_select(self, event):
        """Populates fields when a user is selected."""
        selected_item = self.user_list.selection()
        if selected_item:
            user_data = self.user_list.item(selected_item, "values")
            self.username.set(user_data[0])
            self.role.set(user_data[1])

    def apply_role_filter(self):
        """Applies the selected role filter to the user list."""
        selected_role = self.filter_role.get()
        self.user_list.delete(*self.user_list.get_children())
        if selected_role == "All":
            users = execute_query("SELECT username, role FROM users", fetch=True)
        else:
            users = execute_query("SELECT username, role FROM users WHERE role = ?", (selected_role,), fetch=True)

        for user in users:
            self.user_list.insert("", END, values=(user["username"], user["role"]))

    def search_user(self):
        """Searches for users based on the query."""
        query = self.search_query.get().strip()
        self.user_list.delete(*self.user_list.get_children())

        users = execute_query(
            "SELECT username, role FROM users WHERE username LIKE ?",
            (f"%{query}%",), fetch=True
        )
        for user in users:
            self.user_list.insert("", END, values=(user["username"], user["role"]))

    def reset_password(self):
        """Resets the password for the selected user."""
        username = self.username.get().strip()
        if not username:
            tkinter.messagebox.showerror("Error", "Select a user to reset the password!")
            return

        if username.lower() == "admin":
            tkinter.messagebox.showerror("Error", "The Admin account's password cannot be reset here!")
            return

        new_password = tkinter.simpledialog.askstring("Reset Password", f"Enter new password for {username}:")
        if not new_password:
            tkinter.messagebox.showerror("Error", "Password cannot be empty!")
            return

        hashed_password = hash_password(new_password)
        execute_query("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
        tkinter.messagebox.showinfo("Success", f"Password for {username} has been reset!")

    def add_user(self):
        """Opens a dialog to add a new user with enhancements."""
        add_window = Toplevel ( self.root )
        add_window.title ( "Add User" )
        add_window.geometry ( "400x300" )
        add_window.resizable ( False, False )

        # Variables
        new_username = StringVar ()
        new_password = StringVar ()
        new_role = StringVar ( value="User" )

        # Username
        ttk.Label ( add_window, text="Username:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        username_entry = ttk.Entry ( add_window, textvariable=new_username )
        username_entry.pack ( fill="x", padx=20 )

        # Password
        ttk.Label ( add_window, text="Password:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        password_entry = ttk.Entry ( add_window, textvariable=new_password, show="*" )
        password_entry.pack ( fill="x", padx=20 )

        # Role
        ttk.Label ( add_window, text="Role:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        role_dropdown = ttk.Combobox (
            add_window, textvariable=new_role, values=[ "Admin", "User" ], state="readonly"
        )
        role_dropdown.pack ( fill="x", padx=20 )

        # Save Button
        def save_user():
            username = new_username.get ().strip ()
            password = new_password.get ().strip ()
            role = new_role.get ()

            # Validation
            if not username:
                Messagebox.show_error ( "Username cannot be empty!", title="Error" )
                username_entry.focus ()
                return
            if not password:
                Messagebox.show_error ( "Password cannot be empty!", title="Error" )
                password_entry.focus ()
                return

            try:
                hashed_password = hashlib.sha256 ( password.encode () ).hexdigest ()
                execute_query (
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed_password, role),
                )
                Messagebox.show_info ( "User added successfully!", title="Success" )
                add_window.destroy ()  # Close the dialog
                self.refresh_user_table ( self.user_table )  # Refresh User Management
            except sqlite3.IntegrityError:
                Messagebox.show_error ( "Username already exists!", title="Error" )

        ttk.Button ( add_window, text="Save", command=save_user, bootstyle="success" ).pack ( pady=20 )

        add_window.mainloop ()

    def edit_user(self, tree):
        """Opens a dialog to edit an existing user with enhancements."""
        try:
            selected_item = tree.focus ()
            if not selected_item:
                Messagebox.show_error ( "No user selected.", title="Error" )
                return

            user_data = tree.item ( selected_item, "values" )
            user_id, username, role = user_data

            edit_window = Toplevel ( self.root )
            edit_window.title ( "Edit User" )
            edit_window.geometry ( "400x300" )
            edit_window.resizable ( False, False )

            # Variables
            updated_username = StringVar ( value=username )
            updated_role = StringVar ( value=role )

            # Username
            ttk.Label ( edit_window, text="Username:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
            username_entry = ttk.Entry ( edit_window, textvariable=updated_username )
            username_entry.pack ( fill="x", padx=20 )

            # Role
            ttk.Label ( edit_window, text="Role:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
            role_dropdown = ttk.Combobox (
                edit_window, textvariable=updated_role, values=[ "Admin", "User" ], state="readonly"
            )
            role_dropdown.pack ( fill="x", padx=20 )

            # Save Button
            def save_changes():
                new_username = updated_username.get ().strip ()
                new_role = updated_role.get ()

                # Validation
                if not new_username:
                    Messagebox.show_error ( "Username cannot be empty!", title="Error" )
                    username_entry.focus ()
                    return

                try:
                    execute_query (
                        "UPDATE users SET username = ?, role = ? WHERE id = ?",
                        (new_username, new_role, user_id),
                    )
                    Messagebox.show_info ( "User updated successfully!", title="Success" )
                    edit_window.destroy ()  # Close the dialog
                    self.refresh_user_table ( tree )  # Refresh User Table
                except Exception as e:
                    Messagebox.show_error ( f"Failed to update user: {e}", title="Error" )

            ttk.Button ( edit_window, text="Save", command=save_changes, bootstyle="success" ).pack ( pady=20 )

            edit_window.mainloop ()

        except Exception as e:
            Messagebox.show_error ( f"Unexpected error occurred: {e}", title="Error" )

    def delete_user(self):
        """Deletes a selected user."""
        username = self.username.get().strip()

        if not username:
            tkinter.messagebox.showerror("Error", "Username is required to delete!")
            return

        if username.lower() == "admin":
            tkinter.messagebox.showerror("Error", "The Admin account cannot be deleted!")
            return

        if tkinter.messagebox.askyesno("Confirm", f"Are you sure you want to delete the user '{username}'?"):
            execute_query("DELETE FROM users WHERE username = ?", (username,))
            tkinter.messagebox.showinfo("Success", "User deleted successfully!")
            self.load_users()

    def open_user_dialog(self, title, username="", role="User", is_edit=False):
        """Generic dialog for adding or editing a user."""
        dialog = Toplevel ( self.root )
        dialog.title ( title )
        dialog.geometry ( "400x300" )
        dialog.resizable ( False, False )

        username_var = StringVar ( value=username )
        password_var = StringVar ()
        role_var = StringVar ( value=role )

        ttk.Label ( dialog, text="Username:" ).pack ( anchor="w", padx=20, pady=5 )
        username_entry = ttk.Entry ( dialog, textvariable=username_var, state="normal" if not is_edit else "readonly" )
        username_entry.pack ( fill="x", padx=20 )

        if not is_edit:
            ttk.Label ( dialog, text="Password:" ).pack ( anchor="w", padx=20, pady=5 )
            ttk.Entry ( dialog, textvariable=password_var, show="*" ).pack ( fill="x", padx=20 )

        ttk.Label ( dialog, text="Role:" ).pack ( anchor="w", padx=20, pady=5 )
        ttk.Combobox ( dialog, textvariable=role_var, values=[ "Admin", "User" ], state="readonly" ).pack ( fill="x",
                                                                                                            padx=20 )

        def save_user():
            username = username_var.get ().strip ()
            password = password_var.get ().strip () if not is_edit else None
            role = role_var.get ()

            if not username:
                Messagebox.show_error ( "Username cannot be empty!", title="Error" )
                username_entry.focus ()
                return

            if not is_edit and not password:
                Messagebox.show_error ( "Password cannot be empty!", title="Error" )
                return

            try:
                if is_edit:
                    execute_query ( "UPDATE users SET role = ? WHERE username = ?", (role, username) )
                else:
                    hashed_password = hashlib.sha256 ( password.encode () ).hexdigest ()
                    execute_query (
                        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (username, hashed_password, role),
                    )
                Messagebox.show_info ( f"User {'updated' if is_edit else 'added'} successfully!", title="Success" )
                dialog.destroy ()
                self.load_users ()
            except sqlite3.IntegrityError:
                Messagebox.show_error ( "Username already exists!", title="Error" )

        ttk.Button ( dialog, text="Save", command=save_user ).pack ( pady=20 )