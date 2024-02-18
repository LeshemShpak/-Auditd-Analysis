# Audit Log Analyzer README

## Overview

The Audit Log Analyzer is a Python project designed for the analysis and management of audit logs on Ubuntu servers or computers. Utilizing the auditd system, this script reads, analyzes, and aggregates auditd log files based on predefined rules, then stores the results in a SQLite database. It ensures efficient processing by avoiding duplicate analysis of log entries and managing log file rotation effectively.

## Features

- **Auditd Log Analysis:** Processes auditd log files to extract and categorize information.
- **Rule-based Aggregation:** Groups log entries according to installed auditd rules.
- **SQLite Database Storage:** Saves parsed log data, ensuring no duplicates across runs.
- **Efficient Log Processing:** Identifies and processes only new log entries, managing rotated files seamlessly.
- **Best Practices:** Implements logging, error handling, comments, and external configuration for maintainability and reliability.

## Installation

### Prerequisites

- Python 3.x
- SQLite3
- Ubuntu Server or Computer with auditd installed

### Steps

1. **Install auditd** (if not already installed) on your Ubuntu server:
   ```
   sudo apt-get update
   sudo apt-get install auditd
   ```
2. **Clone the repository:**
   ```
   git clone <repository-url>
   ```
3. **Navigate to the project directory:**
   ```
   cd audit-log-analyzer
   ```
4. **Install required Python packages:**
   ```
   pip install -r requirements.txt
   ```

## Usage

1. **Configure auditd rules** according to your needs and ensure auditd is running.
2. **Run the script:**
   ```
   python3 audit_log_analyzer.py
   ```
3. **Check the output:** The script will process log files and update the database with new entries, avoiding duplicates.

## Configuration

The script uses several constants for configuration, including:

- `LOGS_DIRECTORY`: Directory containing auditd logs.
- `DATABASE_FILENAME`: Name of the SQLite database file.
- `LOGGING_FILE_NAME`: File name for logging script operations.

Adjust these constants in the script as needed to fit your environment.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

Thanks to all users for supporting this project. Special thanks to the Ubuntu and auditd communities for their valuable tools and documentation.
