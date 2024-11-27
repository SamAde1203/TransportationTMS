from ttkbootstrap import Window, ttk
from ttkbootstrap.constants import *
from tkinter import StringVar, Listbox, END
from tkinterweb import HtmlFrame  # To display maps in tkinter
from database import tms_database  # Ensure your database module is properly linked
import tkinter.messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from urllib.parse import quote
import os
import folium
from tkinter import Toplevel
import webview
import webbrowser
from urllib.parse import quote
import os
import tkinter.messagebox
import folium
from tkinter import Menu
from tkinter import Menu, messagebox
import csv
from tkinter import filedialog
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import hashlib
from tkinter import Toplevel, Label, Entry, Button, StringVar, messagebox
import sqlite3
import hashlib
import tkinter.ttk as ttk
from idlelib.tooltip import Hovertip
import plotly.graph_objects as go
from gui.user_management import UserManagement
from database.tms_database import execute_query
from ttkbootstrap.dialogs import Messagebox

ALLOWED_ROLES = [ "Admin", "User" ]  # Define the allowed roles globally or within the class


class TransportManagementSystem:

    def __init__(self, root, username, user_role):
        """
        Initializes the main application.
        :param root: The main Tkinter window
        :param username: Authenticated user's username
        :param user_role: Authenticated user's role ('Admin' or 'User')
        """
        self.root = root
        self.username = username
        self.user_role = user_role

        # Validate the role before initializing the UI
        self.validate_user_role ( self.user_role )

        self.root.title ( "FleetFlow TMS - Transport Management System" )
        self.root.geometry ( "1366x768" )

        # Flags for toggling visibility
        self.show_client_list = True
        self.show_shipment_list = True
        self.show_map = True

        # Client and Shipment data fields
        self.client_name = StringVar ()
        self.client_address = StringVar ()
        self.client_mobile = StringVar ()
        self.client_email = StringVar ()
        self.shipment_client_id = StringVar ()
        self.shipment_route_id = StringVar ()
        self.shipment_vehicle_id = StringVar ()
        self.shipment_driver_id = StringVar ()
        self.shipment_status = StringVar ()

        self.map_file_path = "map.html"

        # Initialize the UI components
        self.initialize_ui ()

    def validate_user_role(self, role):
        """
        Validates the user's role.
        :param role: The user's role to validate
        """
        if role not in ALLOWED_ROLES:
            messagebox.showerror ( "Role Error", f"Invalid role detected: {role}" )
            self.root.destroy ()  # Close the application if the role is invalid

    def initialize_ui(self):
        """Sets up the UI components."""
        self.create_header ()
        self.create_menu_bar ()
        self.create_main_frames ()
        self.create_data_entry_frame ()
        self.create_button_frame ()
        self.create_listbox_frame ()
        self.create_map_frame ()

    def create_menu_bar(self):
        """Creates the menu bar for the application."""
        menu_bar = Menu ( self.root )

        # File menu
        file_menu = Menu ( menu_bar, tearoff=0 )
        file_menu.add_command ( label="Export to CSV", command=self.export_to_csv )
        file_menu.add_command ( label="Import from CSV", command=self.import_from_csv )
        file_menu.add_separator ()
        file_menu.add_command ( label="Exit", command=self.exit_app )
        menu_bar.add_cascade ( label="File", menu=file_menu )

        # View menu
        view_menu = Menu ( menu_bar, tearoff=0 )
        view_menu.add_checkbutton ( label="Client List", command=self.toggle_client_list )
        view_menu.add_checkbutton ( label="Shipment List", command=self.toggle_shipment_list )
        view_menu.add_checkbutton ( label="Map", command=self.toggle_map )
        menu_bar.add_cascade ( label="View", menu=view_menu )

        # Admin menu (only visible to Admins)
        if self.user_role == "Admin":
            admin_menu = Menu ( menu_bar, tearoff=0 )
            admin_menu.add_command ( label="Manage Users", command=self.show_user_management )
            admin_menu.add_command ( label="Save Changes", command=self.save_admin_changes )
            menu_bar.add_cascade ( label="Admin", menu=admin_menu )

        # Help menu
        help_menu = Menu ( menu_bar, tearoff=0 )
        help_menu.add_command ( label="User Manual", command=self.show_user_manual )
        help_menu.add_command ( label="About Application", command=self.show_about )
        menu_bar.add_cascade ( label="Help", menu=help_menu )

        # Attach menu bar to the root window
        self.root.config ( menu=menu_bar )

    def show_user_management(self):
        """Opens the User Management Window (Admin-only)."""
        user_management_window = Toplevel ( self.root )
        user_management_window.title ( "User Management" )
        user_management_window.geometry ( "800x500" )

        # Fetch all users from the database
        users = execute_query ( "SELECT id, username, role FROM users", fetch=True )

        # Table-like display for users
        frame = ttk.Frame ( user_management_window, padding=10 )
        frame.pack ( fill=BOTH, expand=True )

        tree = ttk.Treeview ( frame, columns=("ID", "Username", "Role"), show="headings" )
        tree.heading ( "ID", text="ID" )
        tree.heading ( "Username", text="Username" )
        tree.heading ( "Role", text="Role" )

        # Insert user data into the Treeview
        for user in users:
            tree.insert ( "", END, values=(user [ "id" ], user [ "username" ], user [ "role" ]) )

        tree.pack ( fill=BOTH, expand=True )

        # Buttons for User Management
        button_frame = ttk.Frame ( user_management_window, padding=10 )
        button_frame.pack ( fill=X )

        ttk.Button ( button_frame, text="Add User", command=self.add_user ).pack ( side=LEFT, padx=5 )
        ttk.Button ( button_frame, text="Edit User", command=lambda: self.edit_user ( tree ) ).pack ( side=LEFT,
                                                                                                      padx=5 )
        ttk.Button ( button_frame, text="Delete User", command=lambda: self.delete_user ( tree ) ).pack ( side=LEFT,
                                                                                                          padx=5 )
        ttk.Button ( button_frame, text="Refresh", command=lambda: self.refresh_user_table ( tree ) ).pack ( side=LEFT,
                                                                                                             padx=5 )
        button = ttk.Button ( self.root, text="Save" )
        Hovertip ( button, "Click to save changes." )

    def add_user(self):
        """Opens a dialog to add a new user."""
        add_window = Toplevel ( self.root )
        add_window.title ( "Add User" )
        add_window.geometry ( "400x300" )

        new_username = StringVar ()
        new_password = StringVar ()
        new_role = StringVar ( value="User" )

        Label ( add_window, text="Username:" ).pack ( anchor="w", padx=20, pady=5 )
        Entry ( add_window, textvariable=new_username ).pack ( fill="x", padx=20 )

        Label ( add_window, text="Password:" ).pack ( anchor="w", padx=20, pady=5 )
        Entry ( add_window, textvariable=new_password, show="*" ).pack ( fill="x", padx=20 )

        Label ( add_window, text="Role:" ).pack ( anchor="w", padx=20, pady=5 )
        ttk.Combobox ( add_window, textvariable=new_role, values=[ "Admin", "User" ], state="readonly" ).pack (
            fill="x", padx=20 )

        def save_user():
            username = new_username.get ().strip ()
            password = new_password.get ().strip ()
            role = new_role.get ()

            if not username or not password:
                messagebox.showerror ( "Error", "All fields are required." )
                return

            try:
                hashed_password = hashlib.sha256 ( password.encode () ).hexdigest ()
                execute_query ( "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                                (username, hashed_password, role) )
                messagebox.showinfo ( "Success", "User added successfully!" )
                add_window.destroy ()
                self.show_user_management ()  # Refresh user management
            except sqlite3.IntegrityError:
                messagebox.showerror ( "Error", "Username already exists." )

        ttk.Button ( add_window, text="Save", command=save_user ).pack ( pady=10 )

    def refresh_user_table(self, tree):
        """Refreshes the User Management table."""
        for item in tree.get_children ():
            tree.delete ( item )

        users = execute_query ( "SELECT id, username, role FROM users", fetch=True )
        for user in users:
            tree.insert ( "", END, values=(user [ "id" ], user [ "username" ], user [ "role" ]) )

    def edit_user(self, tree):
        """
        Opens a dialog to edit an existing user.
        """
        try:
            # Check if the main application window still exists
            if not self.root.winfo_exists ():
                raise RuntimeError ( "The main application has been closed." )

            # Get the selected user data from the tree
            selected_item = tree.focus ()
            if not selected_item:
                messagebox.showerror ( "Error", "No user selected." )
                return

            user_data = tree.item ( selected_item, "values" )
            user_id, username, role = user_data

            # Check if an edit_window already exists and destroy it if necessary
            if hasattr ( self, "edit_window" ) and self.edit_window.winfo_exists ():
                self.edit_window.destroy ()

            # Create a new Toplevel window for editing the user
            self.edit_window = Toplevel ( self.root )
            self.edit_window.title ( "Edit User" )
            self.edit_window.geometry ( "400x300" )

            updated_username = StringVar ( value=username )
            updated_role = StringVar ( value=role )

            Label ( self.edit_window, text="Username:" ).pack ( anchor="w", padx=20, pady=5 )
            Entry ( self.edit_window, textvariable=updated_username ).pack ( fill="x", padx=20 )

            Label ( self.edit_window, text="Role:" ).pack ( anchor="w", padx=20, pady=5 )
            ttk.Combobox (
                self.edit_window,
                textvariable=updated_role,
                values=[ "Admin", "User" ],
                state="readonly"
            ).pack ( fill="x", padx=20 )

            def save_changes():
                # Ensure the edit_window still exists before saving
                if not self.edit_window.winfo_exists ():
                    return

                new_username = updated_username.get ().strip ()
                new_role = updated_role.get ().strip ()

                if not new_username:
                    messagebox.showerror ( "Error", "Username cannot be empty." )
                    return

                try:
                    # Update the user in the database
                    execute_query (
                        "UPDATE users SET username = ?, role = ? WHERE id = ?",
                        (new_username, new_role, user_id)
                    )
                    messagebox.showinfo ( "Success", "User updated successfully!" )
                    self.edit_window.destroy ()
                    self.refresh_user_table ( tree )  # Refresh the user table
                except Exception as e:
                    messagebox.showerror ( "Error", f"Failed to update user: {e}" )

            ttk.Button ( self.edit_window, text="Save", command=save_changes ).pack ( pady=20 )

        except RuntimeError as e:
            messagebox.showwarning ( "Warning", str ( e ) )  # Handle gracefully if the main window is closed
        except Exception as e:
            messagebox.showerror ( "Error", f"Unexpected error occurred: {e}" )

    def delete_user(self, tree):
        """Deletes the selected user."""
        selected_item = tree.focus ()
        if not selected_item:
            messagebox.showerror ( "Error", "No user selected." )
            return

        user_data = tree.item ( selected_item, "values" )
        user_id, username, role = user_data

        if username.lower () == "admin":
            messagebox.showerror ( "Error", "The Admin account cannot be deleted!" )
            return

        if messagebox.askyesno ( "Confirm", f"Are you sure you want to delete the user '{username}'?" ):
            try:
                execute_query ( "DELETE FROM users WHERE id = ?", (user_id,) )
                messagebox.showinfo ( "Success", "User deleted successfully!" )
                self.show_user_management ()  # Refresh user management
            except Exception as e:
                messagebox.showerror ( "Error", f"Failed to delete user: {e}" )

    def hash_password(self, password):
        """
        Hashes a password for secure storage.
        :param password: The plain-text password.
        :return: The hashed password.
        """
        return hashlib.sha256 ( password.encode () ).hexdigest ()

    def open_user_management(self):
        """Opens the user management window."""
        if self.user_role != "Admin":
            tkinter.messagebox.showwarning ( "Access Denied", "Only admins can access this feature." )
            return

        user_management_window = Toplevel ( self.root )
        user_management_window.title ( "User Management" )
        user_management_window.geometry ( "600x400" )
        UserManagement ( user_management_window )  # Initialize the UserManagement class

    def show_user_management(self):
        """Opens the User Management Window (Admin-only)."""
        if self.user_role != "Admin":
            messagebox.showwarning ( "Permission Denied", "You do not have access to this feature." )
            return

        user_management_window = Toplevel ( self.root )
        user_management_window.title ( "User Management" )
        user_management_window.geometry ( "600x400" )

        # Fetch all users from the database
        users = execute_query ( "SELECT id, username, role FROM users", fetch=True )

        # Table-like display for users
        frame = ttk.Frame ( user_management_window, padding=10 )
        frame.pack ( fill=BOTH, expand=True )

        tree = ttk.Treeview ( frame, columns=("ID", "Username", "Role"), show="headings" )
        tree.heading ( "ID", text="ID" )
        tree.heading ( "Username", text="Username" )
        tree.heading ( "Role", text="Role" )

        # Insert user data into the Treeview
        for user in users:
            tree.insert ( "", END, values=(user [ "id" ], user [ "username" ], user [ "role" ]) )

        tree.pack ( fill=BOTH, expand=True )

        # Buttons for User Management
        button_frame = ttk.Frame ( user_management_window, padding=10 )
        button_frame.pack ( fill=X )

        ttk.Button ( button_frame, text="Add User", command=self.add_user ).pack ( side=LEFT, padx=5 )
        ttk.Button ( button_frame, text="Edit User", command=lambda: self.edit_user ( tree ) ).pack ( side=LEFT,
                                                                                                      padx=5 )

        ttk.Button ( button_frame, text="Delete User", command=lambda: self.delete_user ( tree ) ).pack ( side=LEFT,
                                                                                                          padx=5 )

        ttk.Button ( button_frame, text="Refresh Dashboard", command=self.refresh_dashboard ).pack ( side=LEFT, padx=5,
                                                                                                 pady=5 )

    def create_client_management(self):
        """Creates the client management tab."""
        ttk.Label(
            self.clients_tab, text="Manage Clients", font=("Helvetica", 20, "bold"), bootstyle="primary"
        ).pack(pady=10)

        # Client list
        self.client_listbox = Listbox(self.clients_tab, font=("Arial", 12), bd=2, relief="solid")
        self.client_listbox.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.client_listbox.bind("<<ListboxSelect>>", self.on_client_select)

        # Add buttons for managing clients
        button_frame = ttk.Frame(self.clients_tab, padding=10, bootstyle="secondary")
        button_frame.pack(fill=X)

        ttk.Button(button_frame, text="Add Client", command=self.add_client, bootstyle="success-outline").pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Client", command=self.delete_client, bootstyle="danger-outline").pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.display_clients, bootstyle="primary-outline").pack(side=RIGHT, padx=5)


    def create_shipment_management(self):
        """Creates the shipment management tab."""
        ttk.Label(
            self.shipments_tab, text="Manage Shipments", font=("Helvetica", 20, "bold"), bootstyle="primary"
        ).pack(pady=10)

        # Shipment list
        self.shipment_listbox = Listbox(self.shipments_tab, font=("Arial", 12), bd=2, relief="solid")
        self.shipment_listbox.pack(fill=BOTH, expand=True, padx=10, pady=10)
        self.shipment_listbox.bind("<<ListboxSelect>>", self.on_shipment_select)

        # Add buttons for managing shipments
        button_frame = ttk.Frame(self.shipments_tab, padding=10, bootstyle="secondary")
        button_frame.pack(fill=X)

        ttk.Button(button_frame, text="Add Shipment", command=self.add_shipment, bootstyle="success-outline").pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Shipment", command=self.delete_shipment, bootstyle="danger-outline").pack(side=LEFT, padx=5)
        ttk.Button(button_frame, text="Refresh", command=self.display_shipments, bootstyle="primary-outline").pack(side=RIGHT, padx=5)


    def add_user(self):
        """Opens a dialog to add a new user."""
        # Ensure only one instance of the dialog is open
        if hasattr ( self, "add_window" ) and self.add_window.winfo_exists ():
            self.add_window.focus ()
            return

        self.add_window = Toplevel ( self.root )
        self.add_window.title ( "Add User" )
        self.add_window.geometry ( "400x300" )

        new_username = StringVar ()
        new_password = StringVar ()
        new_role = StringVar ( value="User" )

        # Form UI
        Label ( self.add_window, text="Username:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        Entry ( self.add_window, textvariable=new_username, font=("Helvetica", 10) ).pack ( fill="x", padx=20 )

        Label ( self.add_window, text="Password:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        Entry ( self.add_window, textvariable=new_password, show="*", font=("Helvetica", 10) ).pack ( fill="x",
                                                                                                      padx=20 )

        Label ( self.add_window, text="Role:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
        ttk.Combobox (
            self.add_window,
            textvariable=new_role,
            values=[ "Admin", "User" ],
            state="readonly",
            font=("Helvetica", 10)
        ).pack ( fill="x", padx=20 )

        def save_user():
            # Validate form input
            username = new_username.get ().strip ()
            password = new_password.get ().strip ()
            role = new_role.get ()

            if not username or not password:
                messagebox.showerror ( "Validation Error", "Username and Password are required." )
                return

            try:
                hashed_password = hashlib.sha256 ( password.encode () ).hexdigest ()
                execute_query (
                    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, hashed_password, role)
                )
                messagebox.showinfo ( "Success", f"User '{username}' added successfully." )
                self.refresh_user_table ( tree=None )  # Refresh user data
                self.add_window.destroy ()
            except sqlite3.IntegrityError:
                messagebox.showerror ( "Error", "Username already exists." )
            except Exception as e:
                messagebox.showerror ( "Error", f"Failed to add user: {e}" )

        ttk.Button ( self.add_window, text="Save", command=save_user, bootstyle="success" ).pack ( pady=10 )

    def edit_user(self, tree):
        """
        Opens a dialog to edit an existing user.
        """
        try:
            selected_item = tree.focus ()
            if not selected_item:
                messagebox.showerror ( "Error", "No user selected." )
                return

            user_data = tree.item ( selected_item, "values" )
            user_id, username, role = user_data

            # Ensure only one instance of the dialog is open
            if hasattr ( self, "edit_window" ) and self.edit_window.winfo_exists ():
                self.edit_window.focus ()
                return

            self.edit_window = Toplevel ( self.root )
            self.edit_window.title ( "Edit User" )
            self.edit_window.geometry ( "400x300" )

            updated_username = StringVar ( value=username )
            updated_role = StringVar ( value=role )

            # Form UI
            Label ( self.edit_window, text="Username:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
            Entry ( self.edit_window, textvariable=updated_username, font=("Helvetica", 10) ).pack ( fill="x", padx=20 )

            Label ( self.edit_window, text="Role:", font=("Helvetica", 12) ).pack ( anchor="w", padx=20, pady=5 )
            ttk.Combobox (
                self.edit_window,
                textvariable=updated_role,
                values=[ "Admin", "User" ],
                state="readonly",
                font=("Helvetica", 10)
            ).pack ( fill="x", padx=20 )

            def save_changes():
                # Validate form input
                new_username = updated_username.get ().strip ()
                new_role = updated_role.get ()

                if not new_username:
                    messagebox.showerror ( "Validation Error", "Username cannot be empty." )
                    return

                try:
                    execute_query (
                        "UPDATE users SET username = ?, role = ? WHERE id = ?",
                        (new_username, new_role, user_id)
                    )
                    messagebox.showinfo ( "Success", f"User '{new_username}' updated successfully." )
                    self.refresh_user_table ( tree )  # Refresh user data
                    self.edit_window.destroy ()
                except Exception as e:
                    messagebox.showerror ( "Error", f"Failed to update user: {e}" )

            ttk.Button ( self.edit_window, text="Save", command=save_changes, bootstyle="success" ).pack ( pady=10 )

        except Exception as e:
            messagebox.showerror ( "Error", f"Unexpected error occurred: {e}" )

    def delete_user(self, tree):
        """Deletes the selected user."""
        selected_item = tree.focus ()
        if not selected_item:
            messagebox.showerror ( "Error", "No user selected." )
            return

        user_data = tree.item ( selected_item, "values" )
        user_id, username, role = user_data

        # Prevent deletion of critical users
        if username.lower () == "admin":
            messagebox.showerror ( "Error", "The Admin account cannot be deleted!" )
            return

        if messagebox.askyesno ( "Confirm", f"Are you sure you want to delete the user '{username}'?" ):
            try:
                execute_query ( "DELETE FROM users WHERE id = ?", (user_id,) )
                messagebox.showinfo ( "Success", "User deleted successfully!" )
                self.show_user_management ()  # Refresh user management
            except sqlite3.Error as e:
                messagebox.showerror ( "Error", f"Failed to delete user: {e}" )

    def confirm_action(self, message, action):
        if messagebox.askyesno ( "Confirm Action", message ):
            action ()

    def save_admin_changes(self):
        """
        Saves the changes made in the Admin menu.
        This function should implement the logic to save any changes made
        (e.g., adding/editing/deleting users).
        """
        try:
            # Placeholder logic: Notify the admin of successful save.
            # Replace this with actual save logic (e.g., database commit).
            messagebox.showinfo ( "Save Changes", "All changes have been successfully saved." )
        except Exception as e:
            messagebox.showerror ( "Error", f"An error occurred while saving changes: {e}" )

    def refresh_dashboard(self):
        self.create_pie_chart ( self.map_frame )  # Refresh the pie chart
        self.update_map ()  # Update the map
        messagebox.showinfo ( "Dashboard Refreshed", "Dashboard has been updated with the latest data." )

    def toggle_client_list(self):
        """Toggles the visibility of the client list."""
        self.show_client_list = not self.show_client_list
        try:
            if self.show_client_list:
                self.client_list.master.pack ( side=LEFT, fill=BOTH, expand=True, padx=(0, 5) )
            else:
                self.client_list.master.pack_forget ()
        except AttributeError:
            tkinter.messagebox.showwarning ( "Error", "Client List widget is not initialized." )

    def toggle_shipment_list(self):
        """Toggles the visibility of the shipment list."""
        self.show_shipment_list = not self.show_shipment_list
        try:
            if self.show_shipment_list:
                self.shipment_list.master.pack ( side=RIGHT, fill=BOTH, expand=True, padx=(5, 0) )
            else:
                self.shipment_list.master.pack_forget ()
        except AttributeError:
            tkinter.messagebox.showwarning ( "Error", "Shipment List widget is not initialized." )

    def toggle_map(self):
        """
        Toggles the visibility of the map popup window.
        If the popup window is not already open, it opens a new map popup.
        If the popup window is open, it closes the window.
        """
        if hasattr ( self, 'map_popup' ) and self.map_popup.winfo_exists ():
            # Close the map popup if it's open
            self.map_popup.destroy ()
            del self.map_popup
            self.show_map = False
        else:
            # Open a new map popup
            self.show_map = True
            self.open_map_popup ()

    def get_table_data(self, table_name):
        """Fetches data and headers for the selected table."""
        if table_name == "Clients":
            data = tms_database.get_clients ()
            headers = [ "id", "name", "address", "mobile", "email" ]
        elif table_name == "Shipments":
            data = tms_database.get_shipments ()
            headers = [ "id", "client_name", "origin", "destination", "status", "shipment_date", "delivery_date" ]
        elif table_name == "Users":
            data = tms_database.get_users ()
            headers = [ "id", "username", "role" ]
        else:
            raise ValueError ( "Invalid table name." )
        return data, headers

    def validate_csv_row(self, row, expected_length):
        """
        Validates the length of a CSV row against the expected length.
        :param row: The CSV row (list of values)
        :param expected_length: The expected number of values in the row
        :raises ValueError: If the row length does not match the expected length
        """
        if len(row) != expected_length:
            raise ValueError(f"Invalid CSV format. Expected {expected_length} columns, but got {len(row)}.")

    def import_from_csv(self):
        """Handles importing data from a CSV file."""
        try:
            file_path = filedialog.askopenfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Open CSV"
            )
            if not file_path:
                return

            with open(file_path, mode="r", newline="", encoding="utf-8") as file:
                reader = csv.reader(file)
                section = None  # Track whether reading clients or shipments

                for row in reader:
                    if not row:
                        continue
                    if row[0] == "Clients":
                        section = "clients"
                        next(reader)  # Skip header row
                    elif row[0] == "Shipments":
                        section = "shipments"
                        next(reader)  # Skip header row
                    elif section == "clients":
                        self.validate_csv_row(row, expected_length=5)
                        tms_database.add_client(row[1], row[2], row[3], row[4])  # Name, Address, Mobile, Email
                    elif section == "shipments":
                        self.validate_csv_row(row, expected_length=7)
                        tms_database.add_shipment(
                            int(row[1]), int(row[2]), int(row[3]), row[4], row[5], row[6], row[7]
                        )

            tkinter.messagebox.showinfo("Success", "Data successfully imported from CSV.")
            self.display_clients()  # Refresh display
            self.display_shipments()  # Refresh display
        except ValueError as ve:
            tkinter.messagebox.showerror("Error", f"CSV Row Error: {ve}")
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to import data: {e}")

    def export_to_csv(self):
        """Handles exporting data to a CSV file."""
        try:
            file_path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                title="Save as CSV"
            )
            if not file_path:
                return

            # Fetch data
            clients = tms_database.get_clients()
            shipments = tms_database.get_shipments()

            with open(file_path, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)

                # Write Clients
                writer.writerow(["Clients"])
                writer.writerow(["ID", "Name", "Address", "Mobile", "Email"])
                for client in clients:
                    writer.writerow([client["id"], client["name"], client["address"], client["mobile"], client["email"]])

                # Write Shipments
                writer.writerow(["Shipments"])
                writer.writerow(
                    ["ID", "Client Name", "Route", "Vehicle", "Driver", "Status", "Shipment Date", "Delivery Date"]
                )
                for shipment in shipments:
                    writer.writerow([
                        shipment["id"], shipment["client_name"], shipment["origin"], shipment["destination"],
                        shipment.get("plate_number", "N/A"), shipment.get("driver_name", "N/A"),
                        shipment["status"], shipment["shipment_date"], shipment["delivery_date"]
                    ])

            tkinter.messagebox.showinfo("Success", "Data exported successfully.")
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to export data: {e}")

    def show_user_manual(self):
        """Displays the user manual."""
        tkinter.messagebox.showinfo (
            "User Manual",
            "FleetFlow TMS User Manual:\n\n"
            "- Use the File menu to export or import data.\n"
            "- Use the View menu to toggle visibility of components.\n"
            "- Contact support for additional help."
        )

    def show_about(self):
        """Displays information about the application."""
        tkinter.messagebox.showinfo (
            "About",
            "FleetFlow TMS\nVersion 1.0\nDeveloped by Sam Adeyemi\n\n"
            "FleetFlow is a transport management system designed to manage "
            "clients, shipments, and routes efficiently."
        )

    def create_header(self):
        """Creates the header section."""
        header_frame = ttk.Frame ( self.root, padding=10, bootstyle="primary" )
        header_frame.pack ( fill=X )

        ttk.Label (
            header_frame,
            text="🚛 FleetFlow TMS - Transport Management System",
            font=("Helvetica", 26, "bold"),
            anchor="center",
            bootstyle="inverse-primary"
        ).pack ( pady=5 )

    def create_main_frames(self):
        """Creates the main layout frames."""
        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=BOTH, expand=True)

        self.data_entry_frame = ttk.Frame(self.main_frame, padding=10, bootstyle="secondary")
        self.data_entry_frame.pack(side=LEFT, fill=Y, padx=(0, 5), pady=5)

        self.listbox_frame = ttk.Frame(self.main_frame, padding=10, bootstyle="secondary")
        self.listbox_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=(5, 0), pady=5)

    def create_data_entry_frame(self):
        """Sets up the data entry form."""
        ttk.Label(self.data_entry_frame, text="Client Information", font=("Helvetica", 14, "bold")).grid(
            row=0, column=0, columnspan=2, sticky=W, pady=5)

        self.create_label_and_entry(self.data_entry_frame, "Client Name", 1, self.client_name)
        self.create_label_and_entry(self.data_entry_frame, "Client Address", 2, self.client_address)
        self.create_label_and_entry(self.data_entry_frame, "Mobile Number", 3, self.client_mobile)
        self.create_label_and_entry(self.data_entry_frame, "Email", 4, self.client_email)

        ttk.Label(self.data_entry_frame, text="Shipment Information", font=("Helvetica", 14, "bold")).grid(
            row=6, column=0, columnspan=2, sticky=W, pady=5)

        self.create_label_and_entry(self.data_entry_frame, "Shipment Client ID", 7, self.shipment_client_id)
        self.create_label_and_entry(self.data_entry_frame, "Shipment Route ID", 8, self.shipment_route_id)
        self.create_label_and_entry(self.data_entry_frame, "Shipment Vehicle ID", 9, self.shipment_vehicle_id)
        self.create_label_and_entry(self.data_entry_frame, "Shipment Driver ID", 10, self.shipment_driver_id)
        self.create_label_and_entry(self.data_entry_frame, "Shipment Status", 11, self.shipment_status)

    def create_label_and_entry(self, frame, label_text, row, variable):
        """Creates a label and entry pair."""
        ttk.Label(frame, text=label_text).grid(row=row, column=0, sticky=W, padx=5, pady=2)
        ttk.Entry(frame, textvariable=variable, width=40).grid(row=row, column=1, padx=5, pady=2)

    def create_button_frame(self):
        """Creates action buttons."""
        button_frame = ttk.Frame(self.root, padding=10, bootstyle="secondary")
        button_frame.pack(fill=X)

        ttk.Button(button_frame, text="Add Client", bootstyle="success-outline", command=self.add_client).pack(
            side=LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Display Clients", bootstyle="primary-outline", command=self.display_clients).pack(
            side=LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Add Shipment", bootstyle="success-outline", command=self.add_shipment).pack(
            side=LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Display Shipments", bootstyle="primary-outline",
                   command=self.display_shipments).pack(side=LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Update Map", bootstyle="warning-outline", command=self.update_map).pack(
            side=LEFT, padx=5, pady=5)
        ttk.Button(button_frame, text="Exit", bootstyle="danger-outline", command=self.exit_app).pack(side=RIGHT,
                                                                                                     padx=5, pady=5)

    def create_listbox_frame(self):
        """Sets up the client and shipment listboxes."""
        client_frame = ttk.Labelframe(self.listbox_frame, text="Client List", padding=10, bootstyle="secondary")
        client_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 5))

        shipment_frame = ttk.Labelframe(self.listbox_frame, text="Shipment List", padding=10, bootstyle="secondary")
        shipment_frame.pack(side=RIGHT, fill=BOTH, expand=True, padx=(5, 0))

        self.client_list = Listbox(client_frame, font=("Arial", 12), bd=2, relief="solid")
        self.client_list.pack(fill=BOTH, expand=True, side=LEFT)
        self.client_list.bind("<<ListboxSelect>>", self.on_client_select)  # Bind event

        self.shipment_list = Listbox(shipment_frame, font=("Arial", 12), bd=2, relief="solid")
        self.shipment_list.pack(fill=BOTH, expand=True, side=LEFT)
        self.shipment_list.bind("<<ListboxSelect>>", self.on_shipment_select)  # Bind event

    def create_map_frame(self):
        """Creates the dashboard with a modern and visually appealing design."""
        self.map_frame = ttk.Labelframe ( self.root, text="🚛 FleetFlow TMS Dashboard", padding=15,
                                          bootstyle="primary" )
        self.map_frame.pack ( fill=BOTH, expand=True, padx=10, pady=10 )

        # Dashboard Header
        header_frame = ttk.Frame ( self.map_frame, padding=10, bootstyle="info" )
        header_frame.pack ( fill=X, pady=10 )

        ttk.Label (
            header_frame,
            text="FleetFlow Dashboard",
            font=("Helvetica", 22, "bold"),
            anchor="center",
            bootstyle="inverse-primary"
        ).pack ()

        # Main Content Section (Key Statistics + Analytics Chart)
        content_frame = ttk.Frame ( self.map_frame, padding=10 )
        content_frame.pack ( fill=BOTH, expand=True, padx=10, pady=10 )

        # Key Statistics Section
        stats_frame = ttk.Labelframe ( content_frame, text="📊 Key Statistics", padding=15, bootstyle="secondary" )
        stats_frame.grid ( row=0, column=0, sticky="nsew", padx=10, pady=10 )

        # Fetch and Display Statistics
        total_clients = len ( tms_database.get_clients () )
        total_shipments = len ( tms_database.get_shipments () )
        total_pending = len (
            [ shipment for shipment in tms_database.get_shipments () if shipment [ 'status' ] == 'Pending' ]
        )
        total_completed = len (
            [ shipment for shipment in tms_database.get_shipments () if shipment [ 'status' ] == 'Delivered' ]
        )

        stats = [
            ("👥 Total Clients", total_clients, "blue"),
            ("📦 Total Shipments", total_shipments, "green"),
            ("⏳ Pending Shipments", total_pending, "orange"),
            ("✅ Completed Shipments", total_completed, "purple"),
        ]

        for label, value, color in stats:
            stat_frame = ttk.Frame ( stats_frame )
            stat_frame.pack ( fill=X, pady=5 )

            ttk.Label ( stat_frame, text=label, font=("Helvetica", 14, "bold") ).pack ( side=LEFT, padx=5 )
            ttk.Label (
                stat_frame,
                text=value,
                font=("Helvetica", 14),
                foreground=color,
                bootstyle="inverse-secondary"
            ).pack ( side=RIGHT, padx=5 )

        # Analytics Chart Section
        chart_frame = ttk.Labelframe ( content_frame, text="📈 Shipment Analytics", padding=15, bootstyle="secondary" )
        chart_frame.grid ( row=0, column=1, sticky="nsew", padx=10, pady=10 )

        self.create_pie_chart ( chart_frame )

        # Configure grid weights for responsive resizing
        content_frame.grid_columnconfigure ( 0, weight=1 )
        content_frame.grid_columnconfigure ( 1, weight=1 )

    def create_pie_chart(self, parent):
        """Generates a visually enhanced pie chart for shipment analytics."""
        # Data for the chart
        shipments = tms_database.get_shipments ()
        status_counts = {
            "Pending": len ( [ shipment for shipment in shipments if shipment [ 'status' ] == 'Pending' ] ),
            "Delivered": len ( [ shipment for shipment in shipments if shipment [ 'status' ] == 'Delivered' ] ),
            "In Transit": len ( [ shipment for shipment in shipments if shipment [ 'status' ] == 'In Transit' ] ),
            "Cancelled": len ( [ shipment for shipment in shipments if shipment [ 'status' ] == 'Cancelled' ] )
        }

        # Prepare data for the pie chart
        labels = list ( status_counts.keys () )
        sizes = list ( status_counts.values () )
        colors = [ "#FFB74D", "#81C784", "#64B5F6", "#E57373" ]  # Modern color palette
        explode = [ 0.1 if status == "Pending" else 0 for status in labels ]  # Highlight Pending shipments

        # Create the pie chart using Matplotlib
        fig, ax = plt.subplots ( figsize=(5, 4), dpi=60 )
        wedges, texts, autotexts = ax.pie (
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            startangle=140,
            colors=colors,
            explode=explode,
            textprops={'fontsize': 10}
        )

        # Style the chart
        ax.set_title ( "Shipment Status Breakdown", fontsize=16, weight="bold" )
        for autotext in autotexts:
            autotext.set_color ( "white" )  # Percentage text in white for better visibility
            autotext.set_fontsize ( 12 )

        # Embed the chart into the Tkinter Frame
        chart_canvas = FigureCanvasTkAgg ( fig, master=parent )
        chart_canvas.draw ()
        chart_canvas.get_tk_widget ().pack ( fill=BOTH, expand=True )

    def create_interactive_chart(self, parent):
        shipments = tms_database.get_shipments ()
        status_counts = {
            "Pending": len ( [ shipment for shipment in shipments if shipment [ "status" ] == "Pending" ] ),
            "Delivered": len ( [ shipment for shipment in shipments if shipment [ "status" ] == "Delivered" ] ),
            "In Transit": len ( [ shipment for shipment in shipments if shipment [ "status" ] == "In Transit" ] ),
            "Cancelled": len ( [ shipment for shipment in shipments if shipment [ "status" ] == "Cancelled" ] )
        }

        fig = go.Figure (
            data=[ go.Pie ( labels=list ( status_counts.keys () ), values=list ( status_counts.values () ) ) ] )
        fig.update_layout ( title="Shipment Status Breakdown" )
        fig.show ()
    def open_map_popup(self):
        try:
            webview.create_window ( "Shipment Routes Map", url=self.map_file_path )
            webview.start ()
        except ImportError:
            normalized_path = os.path.abspath ( self.map_file_path ).replace ( "\\", "/" )
            webbrowser.open ( f"file:///{normalized_path}" )
        except Exception as e:
            tkinter.messagebox.showerror ( "Error", f"Failed to open map popup: {e}" )

    def add_client(self):
        """Handles adding a new client."""
        try:
            name = self.client_name.get().strip()
            address = self.client_address.get().strip()
            mobile = self.client_mobile.get().strip()
            email = self.client_email.get().strip()

            if not name or not mobile:
                raise ValueError("Client Name and Mobile are required.")
            if not mobile.isdigit() or len(mobile) != 10:
                raise ValueError("Mobile number must be a valid 10-digit number.")

            tms_database.add_client(name, address, mobile, email)
            tkinter.messagebox.showinfo("Success", f"Client '{name}' added successfully.")
            self.clear_fields()
            self.display_clients()
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to add client: {e}")

    def add_shipment(self):
        """
        Handles adding a new shipment.
        Validates input fields and inserts the shipment into the database.
        """
        try:
            # Retrieve input values
            client_id = self.shipment_client_id.get ().strip ()
            route_id = self.shipment_route_id.get ().strip ()
            vehicle_id = self.shipment_vehicle_id.get ().strip ()
            driver_id = self.shipment_driver_id.get ().strip () or None  # Optional field
            status = self.shipment_status.get ().strip ()

            # Input validation
            if not client_id or not route_id or not vehicle_id or not status:
                tkinter.messagebox.showerror ( "Validation Error", "All fields except Driver ID are required." )
                return

            if not client_id.isdigit () or not route_id.isdigit () or not vehicle_id.isdigit ():
                tkinter.messagebox.showerror ( "Validation Error",
                                               "Client ID, Route ID, and Vehicle ID must be valid numbers." )
                return

            # Add shipment to the database
            shipment_date = "2024-01-01"  # Placeholder for auto-generated shipment date
            delivery_date = "2024-01-05"  # Placeholder for auto-generated delivery date
            tms_database.add_shipment ( int ( client_id ), int ( route_id ), int ( vehicle_id ), driver_id, status,
                                        shipment_date, delivery_date )
            tkinter.messagebox.showinfo ( "Success", "Shipment added successfully." )

            # Clear the input fields
            self.clear_fields ()

            # Optionally refresh the shipment display
            self.display_shipments ()
        except Exception as e:
            tkinter.messagebox.showerror ( "Error", f"Failed to add shipment: {e}" )

    def display_clients(self):
        """Fetches and displays all clients."""
        try:
            self.client_list.delete(0, END)
            clients = tms_database.get_clients()

            for client in clients:
                self.client_list.insert(
                    END,
                    f"ID: {client['id']} | Name: {client['name']} | Address: {client['address']} | Mobile: {client['mobile']} | Email: {client['email']}"
                )
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to display clients: {e}")

    def display_shipments(self):
        """Fetches and displays all shipments."""
        try:
            self.shipment_list.delete(0, END)
            shipments = tms_database.get_shipments()

            for shipment in shipments:
                self.shipment_list.insert(
                    END,
                    f"ID: {shipment['id']} | Client: {shipment['client_name']} | Route: {shipment['origin']} -> {shipment['destination']} | "
                    f"Vehicle: {shipment.get('plate_number', 'N/A')} | Driver: {shipment.get('driver_name', 'N/A')} | "
                    f"Status: {shipment['status']} | Shipment Date: {shipment['shipment_date']} | Delivery Date: {shipment['delivery_date']}"
                )
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to display shipments: {e}")

    def toggle_theme(self):
        current_theme = self.root.get_theme ()
        new_theme = "flatly" if current_theme == "darkly" else "darkly"
        self.root.set_theme ( new_theme )

    def backup_database(self):
        source = "database.db"
        destination = filedialog.asksaveasfilename ( defaultextension=".db" )
        shutil.copy ( source, destination )
        messagebox.showinfo ( "Backup Successful", f"Database backed up to {destination}." )

    def update_map(self):
        """
        Generates and displays the shipment routes on a map in a popup window.
        """
        try:
            # Ensure the map file is removed before saving a new one
            if os.path.exists ( self.map_file_path ):
                os.remove ( self.map_file_path )

            # Fetch shipment data
            shipments = tms_database.get_shipments ()
            if not shipments:
                tkinter.messagebox.showinfo ( "Info", "No shipment data available to update the map." )
                return

            # Create a map centered at a default location
            shipment_map = folium.Map ( location=[ 54.5, -3.2 ], zoom_start=6 )

            # Add markers and routes to the map
            for shipment in shipments:
                origin = shipment [ 'origin' ]
                destination = shipment [ 'destination' ]
                client_name = shipment [ 'client_name' ]
                status = shipment [ 'status' ]

                # Generate placeholder coordinates (replace with actual data if available)
                origin_coords = [ 54 + 0.1 * shipments.index ( shipment ), -3 + 0.1 * shipments.index ( shipment ) ]
                destination_coords = [ origin_coords [ 0 ] + 0.2, origin_coords [ 1 ] + 0.2 ]

                # Add origin and destination markers
                folium.Marker (
                    location=origin_coords,
                    popup=f"Origin: {origin}<br>Client: {client_name}<br>Status: {status}",
                    tooltip="Origin",
                    icon=folium.Icon ( color="blue", icon="info-sign" )
                ).add_to ( shipment_map )

                folium.Marker (
                    location=destination_coords,
                    popup=f"Destination: {destination}<br>Client: {client_name}<br>Status: {status}",
                    tooltip="Destination",
                    icon=folium.Icon ( color="green", icon="info-sign" )
                ).add_to ( shipment_map )

                # Add a polyline for the route
                folium.PolyLine (
                    locations=[ origin_coords, destination_coords ],
                    color="blue",
                    weight=2.5,
                    tooltip=f"{origin} -> {destination}"
                ).add_to ( shipment_map )

            # Save the map to an HTML file
            shipment_map.save ( self.map_file_path )
            print ( f"Map saved at: {os.path.abspath ( self.map_file_path )}" )

            # Open the map in a popup window
            self.open_map_popup ()
        except Exception as e:
            tkinter.messagebox.showerror ( "Error", f"Failed to update map: {e}" )

    def open_map_popup(self):
        """Opens the map in a popup window."""
        if not self.root.winfo_exists ():
            return  # Do not open map if the root is already destroyed

        try:
            self.map_popup = Toplevel ( self.root )
            self.map_popup.title ( "Shipment Routes Map" )
            self.map_popup.geometry ( "800x600" )

            # Fallback to a web browser if embedded view fails
            try:
                webview.create_window ( "Shipment Routes Map", url=self.map_file_path )
                webview.start ()
            except ImportError:
                normalized_path = os.path.abspath ( self.map_file_path ).replace ( "\\", "/" )
                webbrowser.open ( f"file:///{normalized_path}" )
        except Exception as e:
            tkinter.messagebox.showerror ( "Error", f"Failed to open map popup: {e}" )

    def on_client_select(self, event):
        """Populates client fields on selection."""
        try:
            selected_index = self.client_list.curselection()
            if not selected_index:
                return

            selected_item = self.client_list.get(selected_index[0])
            details = {item.split(":")[0].strip(): item.split(":")[1].strip() for item in selected_item.split("|")}

            self.client_name.set(details["Name"])
            self.client_address.set(details["Address"])
            self.client_mobile.set(details["Mobile"])
            self.client_email.set(details["Email"])
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to populate client details: {e}")

    def on_shipment_select(self, event):
        """Populates shipment fields on selection."""
        try:
            selected_index = self.shipment_list.curselection()
            if not selected_index:
                return

            selected_item = self.shipment_list.get(selected_index[0])
            details = {item.split(":")[0].strip(): item.split(":")[1].strip() for item in selected_item.split("|")}

            self.shipment_client_id.set(details["Client"])
            self.shipment_route_id.set(details["Route"])
            self.shipment_vehicle_id.set(details.get("Vehicle", "N/A"))
            self.shipment_driver_id.set(details.get("Driver", "N/A"))
            self.shipment_status.set(details["Status"])
        except Exception as e:
            tkinter.messagebox.showerror("Error", f"Failed to populate shipment details: {e}")


    def clear_fields(self):
        """Clears all input fields."""
        for var in [
            self.client_name, self.client_address, self.client_mobile, self.client_email,
            self.shipment_client_id, self.shipment_route_id, self.shipment_vehicle_id,
            self.shipment_driver_id, self.shipment_status
        ]:
            var.set("")

    def exit_app(self):
        """Closes the application safely."""
        if tkinter.messagebox.askyesno ( "Exit", "Are you sure you want to exit?" ):
            try:
                # Clean up resources (e.g., map popup)
                if hasattr ( self, 'map_popup' ) and self.map_popup.winfo_exists ():
                    self.map_popup.destroy ()
                    del self.map_popup
            except Exception as e:
                print ( f"Error while closing resources: {e}" )
            finally:
                self.root.quit ()  # Stop the mainloop
                self.root.destroy ()  # Destroy the Tkinter root window


if __name__ == "__main__":
    root = Window(themename="darkly")
    app = TransportManagementSystem(root)
    root.mainloop()
