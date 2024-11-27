import sqlite3
from random import choice, randint
from faker import Faker
import os

# Initialize Faker to generate realistic fake data
fake = Faker("en_GB")

# Define the database path
DB_PATH = os.path.join(os.getcwd(), "fleetflow.db")


def get_db_connection():
    """
    Establishes and returns a connection to the SQLite database.

    Returns:
        sqlite3.Connection: Database connection object.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Allows row access by column name
        return conn
    except sqlite3.Error as e:
        print(f"Error connecting to the database: {e}")
        return None


def generate_clients(n=2000):
    """
    Generates fake client data.

    Args:
        n (int): Number of clients to generate.

    Returns:
        list: List of tuples representing client data.
    """
    clients = []
    for _ in range(n):
        name = fake.name()
        address = fake.address().replace("\n", ", ")
        mobile = f"07{randint(10000000, 99999999)}"
        email = f"{name.split()[0].lower()}{randint(1, 999)}@{choice(['gmail.com', 'yahoo.com', 'outlook.com'])}"
        clients.append((name, address, mobile, email))
    return clients


def generate_vehicles(n=50):
    """
    Generates sample vehicle data.

    Args:
        n (int): Number of vehicles to generate.

    Returns:
        list: List of tuples representing vehicle data.
    """
    vehicles = []
    for _ in range(n):
        plate_number = fake.license_plate()
        model = choice(['Ford F150', 'Mercedes Sprinter', 'Volvo VNL', 'Toyota Prius', 'Tesla Semi'])
        capacity = randint(500, 1500)
        status = choice(['Available', 'In Use', 'Under Maintenance'])
        vehicles.append((plate_number, model, capacity, status))
    return vehicles


def generate_routes(n=100):
    """
    Generates sample route data.

    Args:
        n (int): Number of routes to generate.

    Returns:
        list: List of tuples representing route data.
    """
    routes = []
    for _ in range(n):
        origin = fake.city()
        destination = fake.city()
        while destination == origin:  # Ensure origin and destination are different
            destination = fake.city()
        distance = randint(50, 500)
        estimated_time = randint(1, 10)
        routes.append((origin, destination, distance, estimated_time))
    return routes


def generate_shipments(n=5000, client_ids=None, vehicle_ids=None, route_ids=None):
    """
    Generates fake shipment data.

    Args:
        n (int): Number of shipments to generate.
        client_ids (list): List of client IDs.
        vehicle_ids (list): List of vehicle IDs.
        route_ids (list): List of route IDs.

    Returns:
        list: List of tuples representing shipment data.
    """
    shipments = []
    for _ in range(n):
        client_id = choice(client_ids)
        route_id = choice(route_ids)
        vehicle_id = choice(vehicle_ids)
        driver_id = None  # Placeholder for simplicity
        status = choice(['Pending', 'In Transit', 'Delivered', 'Cancelled'])
        shipment_date = fake.date_this_year()
        delivery_date = fake.date_this_year()
        shipments.append((client_id, route_id, vehicle_id, driver_id, status, shipment_date, delivery_date))
    return shipments


def populate_database():
    """
    Populates the database with sample data.
    """
    conn = get_db_connection()
    if not conn:
        print("Failed to connect to the database.")
        return

    cursor = conn.cursor()

    try:
        # Insert clients
        clients = generate_clients(2000)
        cursor.executemany('''INSERT INTO clients (name, address, mobile, email) VALUES (?, ?, ?, ?)''', clients)
        conn.commit()
        print(f"Inserted {len(clients)} clients.")

        # Insert vehicles
        vehicles = generate_vehicles(50)
        cursor.executemany('''INSERT INTO vehicles (plate_number, model, capacity, status) VALUES (?, ?, ?, ?)''', vehicles)
        conn.commit()
        print(f"Inserted {len(vehicles)} vehicles.")

        # Insert routes
        routes = generate_routes(100)
        cursor.executemany('''INSERT INTO routes (origin, destination, distance, estimated_time) VALUES (?, ?, ?, ?)''', routes)
        conn.commit()
        print(f"Inserted {len(routes)} routes.")

        # Generate shipments
        client_ids = [row["id"] for row in cursor.execute('SELECT id FROM clients').fetchall()]
        vehicle_ids = [row["id"] for row in cursor.execute('SELECT id FROM vehicles').fetchall()]
        route_ids = [row["id"] for row in cursor.execute('SELECT id FROM routes').fetchall()]

        shipments = generate_shipments(5000, client_ids, vehicle_ids, route_ids)
        cursor.executemany('''
            INSERT INTO shipments (client_id, route_id, vehicle_id, driver_id, status, shipment_date, delivery_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)''', shipments)
        conn.commit()
        print(f"Inserted {len(shipments)} shipments.")

    except sqlite3.Error as e:
        print(f"Error occurred while populating database: {e}")
    finally:
        conn.close()


if __name__ == '__main__':
    populate_database()
