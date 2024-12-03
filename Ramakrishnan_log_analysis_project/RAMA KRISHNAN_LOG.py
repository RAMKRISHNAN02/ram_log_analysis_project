import re
import csv
from collections import defaultdict, Counter

# Configuration
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Parse log file and process data
def parse_log_file(log_file):
    ip_requests = defaultdict(int)
    endpoint_requests = defaultdict(int)
    failed_logins = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            # Match IP Address
            ip_match = re.search(r'^(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_requests[ip] += 1
            
            # Match Endpoint
            endpoint_match = re.search(r'"(GET|POST|PUT|DELETE) (.*?) HTTP', line)
            if endpoint_match:
                endpoint = endpoint_match.group(2)
                endpoint_requests[endpoint] += 1

            # Detect Failed Logins
            if '401' in line or "Invalid credentials" in line:
                if ip_match:
                    failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

# Output analysis results
def display_and_save_results(ip_requests, endpoint_requests, failed_logins):
    # Count Requests per IP
    sorted_ips = sorted(ip_requests.items(), key=lambda x: x[1], reverse=True)
    print("IP Address           Request Count")
    for ip, count in sorted_ips:
        print(f"{ip:<20} {count}")

    # Most Frequently Accessed Endpoint
    most_accessed_endpoint = max(endpoint_requests.items(), key=lambda x: x[1])
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    # Detect Suspicious Activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to CSV
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)

        # Write Requests per IP
        csvwriter.writerow(["Requests per IP"])
        csvwriter.writerow(["IP Address", "Request Count"])
        csvwriter.writerows(sorted_ips)

        # Write Most Accessed Endpoint
        csvwriter.writerow([])
        csvwriter.writerow(["Most Accessed Endpoint"])
        csvwriter.writerow(["Endpoint", "Access Count"])
        csvwriter.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])

        # Write Suspicious Activity
        csvwriter.writerow([])
        csvwriter.writerow(["Suspicious Activity"])
        csvwriter.writerow(["IP Address", "Failed Login Count"])
        csvwriter.writerows(suspicious_ips.items())

    print(f"\nResults saved to {OUTPUT_FILE}")

# Main function
if __name__ == "__main__":
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE)
    display_and_save_results(ip_requests, endpoint_requests, failed_logins)
