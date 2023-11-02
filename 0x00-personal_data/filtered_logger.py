#!/usr/bin/env python3
"""Logging and db module"""

import logging
import os
import re
from mysql.connector import connect, MySQLConnection
from mysql.connector.connection import MySQLConnection
from typing import Iterable

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: Iterable):
        """Initialize a new RedactingFormatter."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format a record.

        Args:
            record (logging.LogRecord): A logging record.

        Returns:
            str: A string representation of record in desired format.
        """
        msg = logging.Formatter(self.FORMAT).format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


def filter_datum(
    fields: Iterable, redaction: str, message: str, separator: str
) -> str:
    """Obfuscates fields with redaction in message.

    Args:
        fields (List): a list of strings representing all fields to obfuscate
        redaction (str): a string representing by what the field will be
            obfuscated
        message (str):  a string representing the log line
        separator (str): a string representing by which character is separating
            all fields in the log line(message)

    Returns:
        str: An obfuscated message.
    """
    pattern = r"(?P<field>{0})=[^{1}]*".format("|".join(fields), separator)
    replace = r"\g<field>={}".format(redaction)
    return re.sub(pattern, replace, message)


def get_logger() -> logging.Logger:
    """creates a logger with RedactingFormatter as its formatter.

    Returns:
        logging.Logger: A logger.
    """
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))

    logger = logging.Logger("user_data")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    logger.addHandler(stream_handler)

    return logger


def get_db() -> MySQLConnection:
    """Get a database connection.
    Configured through environment variables.

    ```Bash
    PERSONAL_DATA_DB_USERNAME -> User (Defaults to root)
    PERSONAL_DATA_DB_PASSWORD -> Password (Defaults to "")
    PERSONAL_DATA_DB_HOST -> Host (Defaults to localhost)
    PERSONAL_DATA_DB_NAME -> Database
    ```

    Returns:
        MySQLConnection: A connection to the database.
    """
    config = {
        "user": os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        "password": os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        "host": os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        "database": os.getenv("PERSONAL_DATA_DB_NAME"),
    }

    db = connect(**config)

    return db


def main():
    """Retrieves users from database and logs them"""

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")

    logger = get_logger()

    for user in cursor:
        message = """name={};email={};phone={};ssn={};password={};\
ip={};last_login={};user_agent={};""".format(
            *user
        )
        logger.info(message)
        
    cursor.close()


if __name__ == "__main__":
    main()
