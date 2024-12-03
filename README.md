This project is a Python script that analyzes server log files to extract and process key information. The script is designed to assist in understanding request patterns, identifying frequently accessed resources, and detecting potential security threats such as brute force login attempts.

---

## Features

The script provides the following functionalities:

1. **Count Requests per IP Address**  
   - Extracts all IP addresses from the log file.  
   - Counts the number of requests made by each IP address.  
   - Sorts and displays the results in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**  
   - Extracts endpoints (e.g., URLs or resource paths) from the log file.  
   - Identifies the endpoint accessed the highest number of times.

3. **Detect Suspicious Activity**  
   - Identifies potential brute force login attempts based on failed login entries (e.g., HTTP 401 errors or messages like "Invalid credentials").  
   - Flags IP addresses exceeding a configurable threshold for failed login attempts (default: 10).  

4. **Save Results to CSV**  
   - Outputs the results to a file named `log_analysis_results.csv` .  

---

## Sample Output

### **Requests per IP**  
| IP Address      | Request Count |  
|-----------------|---------------|  
| 192.168.1.1     | 234           |  
| 203.0.113.5     | 187           |  
| 10.0.0.2        | 92            |  
