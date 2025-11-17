import sys
import os
import re
import pandas as pd
import warnings
# Visualization libraries removed for headless/reporting environments

# Suppress FutureWarning about include_groups in resample
warnings.filterwarnings('ignore', category=FutureWarning, message='.*include_groups.*')

# Sample log lines for testing
SAMPLE_LOGS = [
    '192.168.1.10 - - [10/Nov/2025:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:02 +0000] "POST /login HTTP/1.1" 401 512 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:03 +0000] "GET /search?q=union+select HTTP/1.1" 200 2048 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [10/Nov/2025:10:01:01 +0000] "GET /api/users HTTP/1.1" 404 256 "-" "Mozilla/5.0"',
    '10.0.0.5 - - [10/Nov/2025:10:01:02 +0000] "POST /upload?id=1 OR 1=1 HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    '172.16.0.1 - - [10/Nov/2025:10:02:01 +0000] "GET /?param=<script>alert(1)</script> HTTP/1.1" 200 512 "-" "Mozilla/5.0"',
    '172.16.0.1 - - [10/Nov/2025:10:02:02 +0000] "POST /form HTTP/1.1" 403 256 "-" "Mozilla/5.0"',
    '172.16.0.1 - - [10/Nov/2025:10:02:03 +0000] "GET /admin?xss=<img+onload=alert(1)> HTTP/1.1" 200 768 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:04 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:05 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:06 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:07 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
    '192.168.1.10 - - [10/Nov/2025:10:00:08 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
]

# Apache Common Log Format regex with named groups (single-line, robust)
LOG_FORMAT_REGEX = r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s-\s-\s\[(?P<timestamp>.*?)\]\s\"(?P<method>\w+)\s(?P<request>.*?)\sHTTP\/\d\.\d\"\s(?P<status_code>\d{3})\s(?P<size>\d+|-) .*'

# SQL Injection signatures - granular detection patterns (non-capturing groups to avoid pandas warnings)
SQL_SIGNATURES_REGEX = r'(?i)(?:union\s+select|select.*from|or\s+1\s*=\s*1|xp_cmdshell|exec\s|sleep\s*\(\d+\))'

# XSS (Cross-Site Scripting) signatures - granular detection patterns (non-capturing groups)
XSS_SIGNATURES_REGEX = r'(?i)(?:<script|alert\(|onload=|onerror=|javascript:)'



def read_log_file(file_path):
    """Read a log file line by line, yielding each line."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                yield line.rstrip('\n')
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")
        # Return an empty iterator so callers can iterate safely
        return iter([])


def parse_log_line(line, regex_pattern):
    """Parse a single log line using the provided regex pattern.

    Returns a dict of named groups if matched, otherwise None.
    """
    if not line:
        return None
    # Use re.search so regex_pattern can be a string (or compiled pattern)
    match = re.search(regex_pattern, line)
    if match:
        return match.groupdict()
    return None


def export_to_csv(dataframes, filename):
    """Export multiple DataFrames to a single CSV file with clear section headers.

    dataframes: list of (title, dataframe) tuples
    filename: output CSV path
    """
    # Resolve absolute path and ensure directory exists
    abs_path = os.path.abspath(filename)
    dirpath = os.path.dirname(abs_path) or os.getcwd()
    if not os.path.exists(dirpath):
        os.makedirs(dirpath, exist_ok=True)

    try:
        with open(abs_path, 'w', encoding='utf-8', newline='') as f:
            for title, df in dataframes:
                f.write(f"--- {title} ---\n")
                if df is None or df.empty:
                    f.write("No records\n\n")
                else:
                    # Write DataFrame CSV content to the open file handle
                    df.to_csv(f, index=False)
                    f.write("\n")
        return abs_path
    except (OSError, FileNotFoundError) as e:
        # Attempt a fallback to the user's home directory
        home_path = os.path.join(os.path.expanduser('~'), 'incident_report.csv')
        try:
            with open(home_path, 'w', encoding='utf-8', newline='') as f:
                for title, df in dataframes:
                    f.write(f"--- {title} ---\n")
                    if df is None or df.empty:
                        f.write("No records\n\n")
                    else:
                        df.to_csv(f, index=False)
                        f.write("\n")
            return home_path
        except Exception:
            # As a last resort, print the reports to stdout so the user still sees them
            print("Failed to write CSV to disk. Printing consolidated reports to stdout instead:\n")
            for title, df in dataframes:
                print(f"--- {title} ---")
                if df is None or df.empty:
                    print("No records\n")
                else:
                    print(df.to_string(index=False))
                    print('\n')
            return None


def main():
    if len(sys.argv) > 1:
        file_path = sys.argv[1]
        log_lines = []
        for line in read_log_file(file_path):
            # read_log_file returns an iterator; each yielded line is a string
            log_lines.append(line)
        source = f"file: {file_path}"
    else:
        log_lines = SAMPLE_LOGS.copy()
        source = "sample data"

    # Parse each line and collect successful parses
    parsed_logs = []
    for line in log_lines:
        parsed = parse_log_line(line, LOG_FORMAT_REGEX)
        if parsed:
            parsed_logs.append(parsed)

    # Convert parsed logs to a pandas DataFrame
    df = pd.DataFrame(parsed_logs)

    # --- Data cleaning: handle numeric fields ---
    # Replace '-' in 'size' with '0' then convert 'size' and 'status_code' to int
    if 'size' in df.columns:
        df['size'] = df['size'].replace('-', '0')
        df['size'] = pd.to_numeric(df['size'], errors='coerce').fillna(0).astype(int)
    if 'status_code' in df.columns:
        df['status_code'] = pd.to_numeric(df['status_code'], errors='coerce').fillna(0).astype(int)

    # --- Time-series conversion ---
    if 'timestamp' in df.columns:
        # Convert using the exact format required for Apache logs
        df['timestamp'] = pd.to_datetime(
            df['timestamp'], format='%d/%b/%Y:%H:%M:%S %z', errors='coerce'
        )

        # Set the converted timestamp as the DataFrame index
        df = df.set_index('timestamp')

    # Confirmation output: show totals and DataFrame info
    print(f"Loaded {len(log_lines)} lines from {source}. Successfully parsed {len(df)} lines.")
    print("\nDataFrame info:")
    # df.info() prints to stdout; call it to display dtypes and index type
    df.info()

    # --- Detection Algorithms ---
    # 1) Denial of Service (rate limiting) detection
    rate_limited_ips = pd.DataFrame()
    if not df.empty and 'ip' in df.columns:
        # Group by IP and resample per minute, counting requests
        # The timestamp is the index, so we resample while preserving the IP
        rpm = (
            df.groupby('ip')
              .resample('1min')
              .size()
              .reset_index(name='requests_per_minute')
        )

        # Keep only entries with count > 10
        rpm_filtered = rpm[rpm['requests_per_minute'] > 10]
        if not rpm_filtered.empty:
            # Ensure clean integer index
            rpm_filtered = rpm_filtered.reset_index(drop=True)
            rate_limited_ips = rpm_filtered.copy()

    print("\n--- Detected DoS/DDoS Traffic (Top 10 IPs > 10 RPM) ---")
    if not rate_limited_ips.empty:
        # Display with ip, timestamp, and requests_per_minute columns in the correct order
        display_df = rate_limited_ips.sort_values('requests_per_minute', ascending=False).head(10)
        print(display_df[['ip', 'timestamp', 'requests_per_minute']].to_string(index=False))
    else:
        print("No IPs exceeded the RPM threshold.")

    # 2) Scanning / Brute-force detection via error responses
    print("\n--- Detected Scanning/Brute Force (Top 10 IPs by Error Count) ---")
    error_requests = pd.DataFrame()
    if not df.empty and 'status_code' in df.columns and 'ip' in df.columns:
        error_df = df[df['status_code'] >= 400]
        if not error_df.empty:
            # Group by IP and count errors, then reset index to get explicit columns
            error_requests = error_df.groupby('ip').size().reset_index(name='error_count')
            error_requests.reset_index(inplace=True, drop=True)
            error_requests = error_requests.sort_values('error_count', ascending=False)
            print(error_requests.head(10).to_string(index=False))
        else:
            print("No error requests (>=400) found.")
    else:
        print("Insufficient data to compute error-based detections.")

    # 3) SQL Injection detection
    print("\n--- Detected SQL Injection Attacks (Top 10 IPs by Count) ---")
    sqli_attacks = pd.DataFrame()
    if not df.empty and 'request' in df.columns and 'ip' in df.columns:
        # Filter rows where request column matches SQL injection signatures
        sqli_mask = df['request'].fillna('').astype(str).str.contains(SQL_SIGNATURES_REGEX, regex=True, na=False)
        sqli_df = df[sqli_mask]
        if not sqli_df.empty:
            # Group by IP and count attacks, then reset index to get explicit columns
            sqli_attacks = sqli_df.groupby('ip').size().reset_index(name='sqli_count')
            sqli_attacks.reset_index(inplace=True, drop=True)
            sqli_attacks = sqli_attacks.sort_values('sqli_count', ascending=False)
            print(sqli_attacks.head(10).to_string(index=False))
        else:
            print("No SQL injection attack patterns detected.")
    else:
        print("Insufficient data to compute SQL injection detections.")

    # 4) XSS (Cross-Site Scripting) detection
    print("\n--- Detected XSS Attacks (Top 10 IPs by Count) ---")
    xss_attacks = pd.DataFrame()
    if not df.empty and 'request' in df.columns and 'ip' in df.columns:
        # Filter rows where request column matches XSS signatures
        xss_mask = df['request'].fillna('').astype(str).str.contains(XSS_SIGNATURES_REGEX, regex=True, na=False)
        xss_df = df[xss_mask]
        if not xss_df.empty:
            # Group by IP and count attacks, then reset index to get explicit columns
            xss_attacks = xss_df.groupby('ip').size().reset_index(name='xss_count')
            xss_attacks.reset_index(inplace=True, drop=True)
            xss_attacks = xss_attacks.sort_values('xss_count', ascending=False)
            print(xss_attacks.head(10).to_string(index=False))
        else:
            print("No XSS attack patterns detected.")
    else:
        print("Insufficient data to compute XSS detections.")

    # Consolidate the four detection DataFrames and export to a single CSV report
    final_reports = [
        ("DoS/DDoS (RPM > 10)", rate_limited_ips),
        ("Scanning/Brute Force Errors", error_requests),
        ("SQL Injection Attacks", sqli_attacks),
        ("XSS Attacks", xss_attacks),
    ]

    # Export combined reports to CSV
    export_to_csv(final_reports, 'incident_report.csv')
    print("Analysis complete. Incident report saved to incident_report.csv")


if __name__ == "__main__":
    main()
 
