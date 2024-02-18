import re
import time
import sqlite3
import os
import sys
import logging


# Constants
LOGS_DIRECTORY = "/var/log/audit/"
DATABASE_FILENAME = 'audit_logs.db'
LOGGING_FILE_NAME = 'data.log'
LOGGING_FORMAT = '%(asctime)s - %(levelname)s - %(message)s'
# Global variables
# rules, timestamps, logs, and database ids
rules_list_by_key = []
last_time = 0
logs_by_key = {}
rule_key_by_id_in_database = {}


# Extracts date stamp from the log
def find_date_stamp(log):
    marks = r'msg=audit\((\d+\.\d+)'
    try:
        match = re.search(marks, log)
    except re.error as e:
        logging.error(f"REGEX error: {e}")
        return
    if match:
        timestamp = match.group(1)
        return timestamp


# Checks if the date stamp in log is newer than the last run timestamp
def date_stamp_good(log):
    datestamp = find_date_stamp(log)
    try:
        if datestamp and last_time < float(datestamp):
            return True
    except ValueError as e:
        logging.error(f"error converting timestamp to float: {e}")
    return False


# Identifies which rule is associated with the log and updates the logs dict
def certify_which_rule(log):
    if date_stamp_good(log):
        marks = r'key=(.*?)ARCH'
        try:
            key_name = re.findall(marks, log)
        except re.error as e:
            logging.error(f"RE error: {e}")
            return
        # check that there is only one key
        if len(key_name) == 1:
            # first cell contain the key. [1:-2] because: ~key~~
            key_name = key_name[0][1:-2]
            if key_name in rules_list_by_key:
                # append the log data to the list of the specific key
                logs_by_key[key_name].append(log)


# Updates the database with the new logs
def update_the_database(cursor):
    logging.info("Starting to upload logs data to the database")
    for key in logs_by_key:
        logs = logs_by_key[key]
        rule_id = rule_key_by_id_in_database[key]
        for log in logs:
            try:
                cursor.execute('INSERT INTO logs (log_data, rule_id) VALUES (?, ?)', (log, rule_id))
            except sqlite3.Error as e:
                logging.error(f"Cursor error {e}")
    logging.info("Database update completed")
    print("Successfully updated the DataBase :)")


# Start to analyze the log, and categorize them based on rules key
def handel_logs(output):
    log_lines = output.split("type=")
    for log in log_lines[1:]:
        log = "type="+log
        certify_which_rule(log)


# Creates a list of rule keys from the database
def create_rules_key_data(cursor):
    global rules_list_by_key
    try:
        cursor.execute('SELECT rule_key From rules')
    except (sqlite3.OperationalError, sqlite3.Error) as e:
        logging.error(f"Database error: {e}")
    results = cursor.fetchall()
    rules_list_by_key = [rule[0] for rule in results]


# Get the current epoch timestamp
def find_the_time_unix_epoch():
    return str(float(time.time()))


# Get the last run timestamp from the database
def last_date_stamp(cursor):
    global last_time
    try:
        cursor.execute('SELECT timestamp FROM timestamps ORDER BY timestamp DESC LIMIT 1')
    except (sqlite3.OperationalError, sqlite3.Error) as e:
        logging.error(f"Database error: {e}")
    last_stamp = cursor.fetchone()
    if last_stamp:
        last_time = float(last_stamp[0])


# Updates the database with the current timestamp
def update_current_datestamp(cursor):
    logging.info("Updating the data base about the current timestamp")
    try:
        cursor.execute('INSERT INTO timestamps (timestamp) VALUES (?)', (find_the_time_unix_epoch(),))
    except (sqlite3.OperationalError, sqlite3.IntegrityError, sqlite3.Error) as e:
        logging.error(f"Database error: {e}")


# Rule keys to their IDs in the database
def extract_rule_keys_to_ids(cursor):
    global rule_key_by_id_in_database
    try:
        cursor.execute('SELECT id, rule_key FROM rules')
    except (sqlite3.OperationalError, sqlite3.IntegrityError, sqlite3.Error) as e:
        logging.error(f"Database error: {e}")
    results = cursor.fetchall()
    rule_key_by_id_in_database = {rule[1]: rule[0] for rule in results}


# Initializes an empty list for every rule key
def create_rules_dic_by_key():
    for key in rules_list_by_key:
        logs_by_key[key] = []


# Open the SQLite database
def open_database():
    try:
        conn = sqlite3.connect(DATABASE_FILENAME)
        cursor = conn.cursor()
    except sqlite3.Error as e:
        logging.error(f"Database error: {e}")
        sys.exit()
    return conn, cursor


# Lists all log files in the logs directory
def get_log_files(conn):
    try:
        log_files = [entry.name for entry in os.scandir(LOGS_DIRECTORY)
                     if entry.name.startwith('audit.log') and entry.is_file()]
    except PermissionError:
        print("There is a PermissionError, there is no permission to access the file."
              " Try to run program as sudo")
        logging.error("PermissionError")
        close_database(conn)
        sys.exit()
    except FileNotFoundError:
        print("There is a FileNotFoundError, probably the {0} directory does not exist".format(LOGS_DIRECTORY))
        logging.error("FileNotFoundError")
        close_database(conn)
        sys.exit()
    except Exception as e:
        print(e)
        logging.error(e)
        close_database(conn)
        sys.exit()

    return log_files


# Commits changes to the database and closes the database
def close_database(conn):
    logging.info("Committing changes and closing the database")
    try:
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Database commit error: {e}")
    finally:
        conn.close()


# Reads a file from the given path
def read_file(full_path):
    content = None
    try:
        with open(full_path, 'r') as file:
            content = file.read()
    except PermissionError:
        print("There is a PermissionError, there is no permission to read the file."
              "Try to run program as sudo")
        logging.error("PermissionError")
    except UnicodeDecodeError:
        print(f"There is a UnicodeDecodeError")
        logging.error("UnicodeDecodeError")
    except Exception as e:
        print(e)
        logging.error(e)
    return content


# Checks for new audit logs and updates the database
def check_changes_and_update(cursor):
    if all(len(lst) == 0 for lst in logs_by_key.values()):
        print("There is no new audit logs. Try to restart the auditd service")
        logging.warning("There is no new audit logs. Try to restart the auditd service")
    else:
        update_the_database(cursor)


# Start to analyze the log file
def handel_log_file(log_file):
    logging.debug(f"Start reading logs from: {log_file}")
    full_path = os.path.join(LOGS_DIRECTORY, log_file)
    content = read_file(full_path)
    if content:
        handel_logs(content)


def main():
    # Set up logging configuration
    logging.basicConfig(filename=LOGGING_FILE_NAME, level=logging.DEBUG, format=LOGGING_FORMAT)
    logging.info("Open data base and extract useful data")
    conn, cursor = open_database()

    # Extract data from the database and create local database
    last_date_stamp(cursor)
    create_rules_key_data(cursor)
    create_rules_dic_by_key()
    extract_rule_keys_to_ids(cursor)

    # start reding and analyzing the log files
    log_files = get_log_files(conn)
    if log_files:
        for log_file in log_files:
            handel_log_file(log_file)

    check_changes_and_update(cursor)

    update_current_datestamp(cursor)
    close_database(conn)
    logging.info("Process completed")


if __name__ == '__main__':
    main()
