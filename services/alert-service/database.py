import os
import mysql.connector


def get_db_connection():
    connection = mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", "Root123"),
        database=os.getenv("DB_NAME", "threat_intelligence_db")
    )

    return connection