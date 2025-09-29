import re
from collections import Counter

# --- 1. Configuration (The Regex Pattern) ---
# This is a simpler regex to extract IP, Timestamp, Method, Path, and Status Code.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'           # IP address
    r'.*?'                      # Skip user and id fields
    r'\[(?P<timestamp>[^\]]+)\]\s+' # Timestamp
    r'"(?P<request>[^"]*)"\s+'  # The full request (Method, Path, Version)
    r'(?P<status>\d{3})\s+'     # HTTP Status Code
    r'(?P<size>\S+)'            # Response Size
)

def simple_log_analyzer(file_path):
    """
    Parses a log file and aggregates the count of all HTTP Status Codes.
    """
    status_codes = []
    total_lines = 0
    parsed_lines = 0

    print(f"--- Starting Analysis of {file_path} ---")

    try:
        with open(file_path, 'r') as f:
            for line in f:
                total_lines += 1
                match = LOG_PATTERN.search(line)
                
                if match:
                    # Extract the status code from the matched groups
                    status = match.group('status')
                    status_codes.append(status)
                    parsed_lines += 1
                # Lines that don't match are simply ignored
                    
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return

    # --- 2. Aggregation and Reporting ---
    
    if not status_codes:
        print("No valid log entries were parsed.")
        return
        
    # Use the Counter object for simple, fast frequency aggregation
    status_counts = Counter(status_codes)
    
    print("\n--- Summary Report ---")
    print(f"Total Lines Read: {total_lines}")
    print(f"Successfully Parsed Entries: {parsed_lines}")
    print(f"Skipped Entries: {total_lines - parsed_lines}")
    
    print("\n--- HTTP Status Code Breakdown (Top 5) ---")
    
    # Print the top 5 most common status codes
    for status, count in status_counts.most_common(5):
        print(f"Status {status}: {count}")

# --- Main Execution ---

# 1. Create a dummy log file content for testing
DUMMY_LOG_CONTENT = """
192.168.1.1 - - [29/Sep/2025:10:00:01 +0200] "GET /index.html HTTP/1.1" 200 1024
192.168.1.2 - - [29/Sep/2025:10:00:05 +0200] "GET /images/logo.png HTTP/1.1" 200 5678
192.168.1.3 - - [29/Sep/2025:10:00:10 +0200] "POST /submit/form HTTP/1.1" 404 150
192.168.1.4 - - [29/Sep/2025:10:00:15 +0200] "GET /api/data HTTP/1.1" 500 200
192.168.1.1 - - [29/Sep/2025:10:00:20 +0200] "GET /index.html HTTP/1.1" 200 1024
10.0.0.5 - - [29/Sep/2025:10:01:00 +0200] "GET /styles.css HTTP/1.1" 200 500
# This is a malformed line that should be skipped
10.0.0.6 - - [29/Sep/2025:10:01:05 +0200] "GET /api/data 500
10.0.0.7 - - [29/Sep/2025:10:01:10 +0200] "GET /config.xml HTTP/1.1" 403 100
"""

DUMMY_LOG_PATH = "simple_log.log"

# Save the dummy content to a file
with open(DUMMY_LOG_PATH, "w") as f:
    f.write(DUMMY_LOG_CONTENT)

if __name__ == "__main__":
    simple_log_analyzer(DUMMY_LOG_PATH)
