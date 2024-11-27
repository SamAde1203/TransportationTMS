import hashlib
import sqlite3
import os

# Define the path for the SQLite database
DB_PATH = os.path.join(os.getcwd(), "fleetflow.db")


def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Enables access to rows as dictionaries
        return conn
    except sqlite3.Error as e:
        print(f"Database connection error: {e}")
        return None


def execute_query(query, params=None, fetch=False):
    """
    Executes a database query.

    Args:
        query (str): The SQL query to execute.
        params (tuple, optional): Parameters for the query.
        fetch (bool): Whether to fetch results. Defaults to False.

    Returns:
        list: Fetched rows if `fetch=True`, otherwise an empty list.
    """
    conn = get_db_connection()
    if not conn:
        return []

    try:
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)

        if fetch:
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        if conn:
            conn.close()

def get_users():
    """Fetches all users."""
    query = "SELECT id, username, role FROM users"
    return execute_query(query, fetch=True)

def add_user(username, hashed_password, role):
    """Adds a new user."""
    query = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
    execute_query(query, (username, hashed_password, role))

def update_user(user_id, username, role):
    """Updates a user's details."""
    query = "UPDATE users SET username = ?, role = ? WHERE id = ?"
    execute_query(query, (username, role, user_id))

def delete_user(user_id):
    """Deletes a user."""
    query = "DELETE FROM users WHERE id = ?"
    execute_query(query, (user_id,))

def create_users_table():
    """Creates the users table if it doesn't already exist."""
    query = '''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'User' -- Role can be 'Admin' or 'User'
    )
    '''
    execute_query(query)


def create_tables():
    """Creates the necessary database tables if they do not exist."""
    queries = [
        '''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            address TEXT,
            mobile TEXT NOT NULL,
            email TEXT
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS routes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            origin TEXT NOT NULL,
            destination TEXT NOT NULL,
            distance INTEGER,
            estimated_time INTEGER
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS vehicles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plate_number TEXT UNIQUE,
            model TEXT,
            capacity INTEGER,
            status TEXT
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS drivers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mobile TEXT,
            license_number TEXT UNIQUE,
            vehicle_id INTEGER,
            FOREIGN KEY(vehicle_id) REFERENCES vehicles(id)
        )
        ''',
        '''
        CREATE TABLE IF NOT EXISTS shipments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL,
            route_id INTEGER NOT NULL,
            vehicle_id INTEGER,
            driver_id INTEGER,
            status TEXT NOT NULL,
            shipment_date TEXT,
            delivery_date TEXT,
            FOREIGN KEY(client_id) REFERENCES clients(id),
            FOREIGN KEY(route_id) REFERENCES routes(id),
            FOREIGN KEY(vehicle_id) REFERENCES vehicles(id),
            FOREIGN KEY(driver_id) REFERENCES drivers(id)
        )
        '''
    ]

    for query in queries:
        execute_query(query)

def hash_password(password):
    """Hashes the password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

# CRUD Operations for Clients
def add_client(name, address, mobile, email):
    """Adds a new client to the database."""
    query = '''
        INSERT INTO clients (name, address, mobile, email)
        VALUES (?, ?, ?, ?)
    '''
    execute_query(query, (name, address, mobile, email))


def get_clients():
    """Fetches all clients from the database."""
    query = 'SELECT * FROM clients'
    return execute_query(query, fetch=True)


def update_client(client_id, name, address, mobile, email):
    """Updates a client's information."""
    query = '''
        UPDATE clients
        SET name = ?, address = ?, mobile = ?, email = ?
        WHERE id = ?
    '''
    execute_query(query, (name, address, mobile, email, client_id))


def delete_client(client_id):
    """Deletes a client from the database."""
    query = 'DELETE FROM clients WHERE id = ?'
    execute_query(query, (client_id,))


# CRUD Operations for Routes
def add_route(origin, destination, distance, estimated_time):
    """Adds a new route to the database."""
    query = '''
        INSERT INTO routes (origin, destination, distance, estimated_time)
        VALUES (?, ?, ?, ?)
    '''
    execute_query(query, (origin, destination, distance, estimated_time))


def get_routes():
    """Fetches all routes from the database."""
    query = 'SELECT * FROM routes'
    return execute_query(query, fetch=True)


def update_route(route_id, origin, destination, distance, estimated_time):
    """Updates a route's information."""
    query = '''
        UPDATE routes
        SET origin = ?, destination = ?, distance = ?, estimated_time = ?
        WHERE id = ?
    '''
    execute_query(query, (origin, destination, distance, estimated_time, route_id))


def delete_route(route_id):
    """Deletes a route from the database."""
    query = 'DELETE FROM routes WHERE id = ?'
    execute_query(query, (route_id,))


# CRUD Operations for Shipments
def add_shipment(client_id, route_id, vehicle_id, driver_id, status, shipment_date, delivery_date):
    """Adds a new shipment to the database."""
    query = '''
        INSERT INTO shipments (client_id, route_id, vehicle_id, driver_id, status, shipment_date, delivery_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    '''
    execute_query(query, (client_id, route_id, vehicle_id, driver_id, status, shipment_date, delivery_date))


def get_shipments():
    """Fetches all shipments, including details about clients, routes, and vehicles."""
    query = '''
        SELECT shipments.id, shipments.status, shipments.shipment_date, shipments.delivery_date,
               clients.name AS client_name, routes.origin, routes.destination, vehicles.plate_number,
               drivers.name AS driver_name
        FROM shipments
        LEFT JOIN clients ON shipments.client_id = clients.id
        LEFT JOIN routes ON shipments.route_id = routes.id
        LEFT JOIN vehicles ON shipments.vehicle_id = vehicles.id
        LEFT JOIN drivers ON shipments.driver_id = drivers.id
    '''
    return execute_query(query, fetch=True)


def update_shipment(shipment_id, status, delivery_date):
    """Updates a shipment's status or delivery date."""
    query = '''
        UPDATE shipments
        SET status = ?, delivery_date = ?
        WHERE id = ?
    '''
    execute_query(query, (status, delivery_date, shipment_id))


def delete_shipment(shipment_id):
    """Deletes a shipment from the database."""
    query = 'DELETE FROM shipments WHERE id = ?'
    execute_query(query, (shipment_id,))


if __name__ == '__main__':
    create_tables()
    print("Database and tables initialized successfully.")
