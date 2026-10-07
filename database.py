import os
import mysql.connector
from dotenv import load_dotenv


# --------------------------------------------------
# Load the .env file from this exact project folder
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_FILE = os.path.join(BASE_DIR, ".env")

load_dotenv(ENV_FILE, override=True)


# --------------------------------------------------
# Read database settings ONCE when this module loads
# --------------------------------------------------

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")


# --------------------------------------------------
# Database connection function
# --------------------------------------------------

def get_connection():

    connection = mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

    return connection