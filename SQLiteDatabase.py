import sqlite3


class SQLiteDatabase:
    """
    Database context manager
    """

    def __init__(self, database_file_name: str) -> None:
        self.database_file_name = database_file_name

    def __enter__(self):
        self.connection = sqlite3.connect(self.database_file_name)
        self.cursor = self.connection.cursor()
        return self

    def __exit__(self, exception_type, exc_val, traceback):
        self.cursor.close()
        self.connection.close()
