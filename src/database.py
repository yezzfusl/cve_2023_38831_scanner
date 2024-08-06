import sqlite3
import logging
from datetime import datetime

class Database:
    def __init__(self, db_file='scan_results.db'):
        self.db_file = db_file
        self.conn = None
        self.create_table()

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.db_file)
            return self.conn
        except sqlite3.Error as e:
            logging.error(f"Error connecting to database: {e}")
            return None

    def create_table(self):
        query = '''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            is_vulnerable BOOLEAN NOT NULL,
            winrar_version TEXT,
            integrity_check TEXT,
            memory_scan_result TEXT,
            network_scan_result TEXT,
            sandbox_result TEXT
        )
        '''
        try:
            with self.connect() as conn:
                conn.execute(query)
        except sqlite3.Error as e:
            logging.error(f"Error creating table: {e}")

    def insert_scan_result(self, is_vulnerable, winrar_version, integrity_check, memory_scan_result, network_scan_result, sandbox_result):
        query = '''
        INSERT INTO scan_results (timestamp, is_vulnerable, winrar_version, integrity_check, memory_scan_result, network_scan_result, sandbox_result)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        '''
        try:
            with self.connect() as conn:
                conn.execute(query, (
                    datetime.now().isoformat(),
                    is_vulnerable,
                    winrar_version,
                    integrity_check,
                    memory_scan_result,
                    network_scan_result,
                    sandbox_result
                ))
            logging.info("Scan result inserted into database")
        except sqlite3.Error as e:
            logging.error(f"Error inserting scan result: {e}")

    def get_all_scan_results(self):
        query = "SELECT * FROM scan_results ORDER BY timestamp DESC"
        try:
            with self.connect() as conn:
                cursor = conn.execute(query)
                return cursor.fetchall()
        except sqlite3.Error as e:
            logging.error(f"Error retrieving scan results: {e}")
            return []
