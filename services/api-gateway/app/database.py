import mysql.connector


def get_db_connection():
    connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Root123",
        database="threat_intelligence_db"
    )

    return connection