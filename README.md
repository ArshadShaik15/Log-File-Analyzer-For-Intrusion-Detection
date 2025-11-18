# Log-File-Analyzer-For-Intrusion-Detection<br>

<br>

### Project: Log File Analyzer for Intrusion Detection<br>

Automated Python-based pipeline for transforming raw web server access logs into actionable security intelligence.<br>
<br>
<br>
<br>

### 🎯 Project Objective:<br>
<br>

<p align="left">The goal of this project is to build a lightweight, Python-based log file analyzer that parses server logs (web access logs and SSH auth logs), detects suspicious activity, and produces structured forensic visualizations to accelerate incident response.</p>
<strong>This project automates:</strong><br>
<br>

• Parsing Apache access logs using Regex + Pandas

• Detecting DoS/DDoS spikes, Brute-Force attempts, SQL Injection, and XSS attacks

• Producing structured incident reports

• Generating high-quality threat visualizations using Matplotlib<br>
<br>
<br>
<br>

### 💻 Lab Setup:<br>
<br> 

| Component | Version / Requirement                    |
| --------- | ---------------------------------------- |
| Python    | 3.8+  ( I used Python 3.12 )             |
| OS        | Windows / Linux / macOS                  |
| Libraries | pandas, matplotlib, numpy, re (Regex)    |
| Input     | Apache Access Logs (`access.log`)        |
| Output    | `incident_report.csv`, PNG visualization |
<br>
<br>
<br>

### 🚀 How to Build & Run the Project:<br>
<br>

<strong>1. Install Dependencies</strong>
  ```
  pip install pandas matplotlib numpy
  ```
<br>

<strong>2. Commands to Run -</strong> Processes your log file, performs detection, and writes a consolidated report.
  ```
# Run the analyzer (parses log, detects threats, exports incident_report.csv)
python src/analyzer.py data/access.log

# Create the threat visualization (PNG)
python src/threat_visualization.py

  ```
<br>

<strong>3. Implementation overview</strong> ( what happens when you run the command - ```python src/analyzer.py data/access.log``` )<br>

- ```src/analyzer.py``` — core analysis pipeline

- ```analyzer.py``` implements a simple, reproducible ETL (Extract, Transform, Load) → analysis → report pipeline:<br>
<br>

<strong>I. Ingestion (read_log_file)</strong>
<pre>
• Streams the log file line-by-line (<mark>with open(...)</mark>), which keeps memory usage low for large files.
  
• If no file argument is provided, a small sample dataset is used for quick testing.
</pre><br>
<strong>II. Parsing (parse_log_line)</strong>
<pre>
• Uses a robust Apache Common Log Format regex with named capture groups to extract fields:
  • <mark>ip</mark>, <mark>timestamp</mark>, <mark>method</mark>, <mark>request</mark>, <mark>status_code</mark>, <mark>size</mark>
  
• Named groups make it trivial to convert parsed results directly into a list-of-dicts and then into a Pandas DataFrame.
  
</pre><br>

<strong>III. Data Cleaning & Type conversion</strong>
<pre>
• Replaces <mark>-</mark> sizes with <mark>0</mark> and coerces <mark>size</mark> and <mark>status_code</mark> to integers.

• Converts the <mark>timestamp</mark> string to a timezone-aware <mark>datetime</mark> using <mark>pd.to_datetime(..., format='...')</mark>.

• Sets the timestamp as the DataFrame index <mark>(DatetimeIndex)</mark> to enable time-series operations.
</pre><br>
<strong>IV. Time-series & grouping (core detection building blocks)</strong>
<pre>
• For DoS detection: groups by <mark>ip</mark> and <mark>resamples</mark> per minute to compute Requests Per Minute (RPM).

• For scanning/brute force: filters requests with <mark>status_code >= 400</mark> and <mark>groupby('ip').size()</mark> to get error counts.

• For SQLi & XSS detection: uses regex pattern matching on the <mark>request</mark> column to find payloads (e.g., <mark>UNION SELECT</mark>, <mark>OR 1=1</mark>, <mark><script></mark>, <mark>alert()</mark>), then <mark>groupby('ip')</mark> for counts.
</pre><br>

<strong>V. Thresholding & results</strong>
<pre>
• Example threshold: RPM > 10 (configurable in code).

• Produces top offenders for each category (DoS, error-based brute force, SQLi, XSS) and prints them to the console.
</pre><br>

<strong>VI. Reporting (export_to_csv)</strong>
<pre>
• Consolidates dataframes (per category) and writes them into a single, human-readable <mark>incident_report.csv</mark>.

• If file write fails, falls back to the home directory; if that fails, prints the report to stdout so no data is lost.
</pre><br>

<strong>VII. Output after running</strong>
<pre>
• Console log with summary (e.g., “Loaded 13853 lines … Successfully parsed 13853 lines.”)

• <mark>output/incident_report.csv</mark> — structured CSV sections for each detection module

• <mark>output/output.txt</mark> (if you redirect output) — contains full printed analysis (example included in repo)
</pre>
<br>  <img width="1124" height="1067" alt="Screenshot 2025-11-18 183103" src="https://github.com/user-attachments/assets/8b723f41-655a-4876-9850-0f7fd6f620c1" />  <br>
<br>
<br>

<strong>4. Implementation overview</strong> ( what happens when you run the command - ```python threat_visualization``` )<br>

- ```src/threat_visualization.py``` — visualization & validation

- ```threat_visualization.py``` generates a forensic figure used in the report:<br>
<br>

<strong>I. Data creation</strong> (```create_dataframes```)
<pre>
Prepares two DataFrames:

• <mark>df_temporal</mark> with (Timestamp, requests_per_minute) — parsed to <mark>datetime</mark> and sorted.

• <mark>df_attribution</mark> with counts per threat category for two top IPs (for categorical comparison).
</pre><br>
<strong>II. Plotting</strong> (```plot_threat_visualization```)
<pre>
Creates two vertically stacked subplots:

• Top: Temporal line plot (RPM vs time) with time formatted as <mark>HH:MM:SS</mark> to show spikes.

• Bottom: Grouped bar chart comparing two attacker IPs across threat categories (Brute Force, SQLi, XSS).

• Annotates bar heights and saves a high-resolution PNG: <mark>Threat_Visualization_Validated.png</mark>.
</pre><br>
<strong>III. Output after running</strong>
<pre>
• <mark>output/Threat_Visualization_Validated.png</mark> — the dual-plot image used in the report.
</pre>
<br>  <img width="1919" height="1199" alt="Screenshot 2025-11-15 221924" src="https://github.com/user-attachments/assets/e3e36143-3eed-4a15-a7ad-5503f771ceef" />  <br>
<br>
<br>
<br>

### 🔍 Detection Capabilities:<br>
<br>

<strong>1. DoS/DDoS Rate-Limiting Detection</strong><br>

   • Resamples traffic per minute<br>
   • Flags IPs > 10 requests per minute<br>

Output Sample:<br>
<pre>
ip                timestamp                 RPM
192.168.4.164     2016-12-22 15:19:00       2908
192.168.4.164     2016-12-22 15:20:00       2659
192.168.4.164     2016-12-22 15:21:00       1416
</pre><br>

<strong>2. Scanning & Brute Force Detection</strong><br>

• Counts HTTP error codes (≥400) per IP.<br>
<pre>
ip                  error_count
192.168.4.164       2620
192.168.4.25         979
</pre><br>

<strong>3. SQL Injection Detection</strong><br>

• Regex-based detection using signatures:<br>
<pre>
'UNION SELECT', 'OR 1=1', 'exec', 'sleep()'
</pre>
Output Sample:<br>
<pre>
ip                  sqli_count
192.168.4.164       165
192.168.4.25         44
</pre><br>

<strong>4. XSS Attack Detection</strong><br>

• Detects signatures like:<br>
<pre>
<script> , alert(), onload= , onerror=
</pre>
Output Sample:<br>
<pre>
ip                  xss_count
192.168.4.164       136
192.168.4.25         29
</pre><br>
<br>


### ⚙️ Internal Workflow:<br>
<br>

<strong>ETL Pipeline</strong><br>

• Extract – Reads log files line-by-line<br>

• Transform – Regex parses IP, timestamp, request, status code<br>

• Load – Loads into Pandas DataFrame<br>

• Analyze – Applies detection algorithms<br>

• Report – Exports structured CSV + visualization<br>
<br>
<br>
<br>

### 📊 Results:<br>
<br>

<strong>1. Console Output (analyzer.py)</strong><br>

Located in output/output.txt<br>
✔ Successfully parsed 13853 lines<br>
✔ DoS/DDoS traffic spikes detected<br>
✔ Brute force attempts identified<br>
✔ SQLi & XSS attacks flagged<br>

Generated file:<br>
📊 Report exported to incident_report.csv<br>
📄 output.txt<br>
<br>

<strong>2. Visualization Output</strong>

✔ Temporal DoS/DDoS Traffic (RPM over time)&nbsp; - &nbsp;Shows dramatic spikes associated with high-volume attacks.

✔ Attacker Contribution Graph&nbsp; - &nbsp;Compares top malicious IPs across categories (Brute Force, SQLi, XSS).<br>

Generated file:<br>
📈 Threat_Visualization_Validated.png<br>
<br>
<br>
<br>

### 🧩 Challenges Faced:<br>
<br>

<strong>1. Parsing inconsistent timestamps</strong><br>

Apache logs use complex formats, requiring explicit datetime parsing.<br>
<br>

<strong>2. Ensuring regex precision</strong><br>

Improper parsing → false positives/negatives.<br>
Solution: robust patterns with named capture groups.<br>
<br>

<strong>3. Handling large-scale logs</strong><br>

Used streaming read (for line in file) + optimized DataFrames.<br>
<br>

<strong>4. Differentiating attacks</strong><br>

DoS/DDoS vs high traffic required time-series pattern recognition.<br>
<br>
<br>
<br>

### 📌 Future Enhancements (Optional Add-Ons)<br>
<br>

• Add geolocation of IPs<br>

• Integrate AbuseIPDB lookups<br>

• Build a real-time dashboard (e.g., Streamlit)<br>

• Add RPS-based DoS detection<br>

• Expand detection categories (CSRF, Command Injection, etc.)<br>
<br>
<br>
<br>

### 📝 Summary:<br>
<br>

<p align="left">• The project successfully implemented a complete <strong>Log File Analyzer for Intrusion Detection</strong>, capable of parsing Apache access logs, extracting structured information, and applying security-focused detection logic.</p>

<p align="left">• Using <strong>regular expressions, Pandas, and time-series analysis</strong>, the system efficiently processed over <strong>13,500+ log entries</strong>, converting raw log data into meaningful intelligence.</p>

<p align="left">• Multiple attack vectors were automatically identified, including <strong>DoS/DDoS bursts, brute-force attempts, SQL Injection, and XSS attacks</strong>, each supported by clear counts and attacker attribution.</p>

<p align="left">• The analyzer produced a consolidated <strong>incident_report.csv</strong> summarizing all detected threats, enabling quick review for analysts or automated pipelines.</p>

<p align="left">• The visualization module generated a dual-plot chart showing temporal spikes in attack traffic and a comparative breakdown of malicious IP activity, offering a strong visual foundation for incident reporting and forensic analysis.</p>

<p align="left">Overall, the project demonstrates an effective pipeline from ingesting raw server logs → performing structured analysis → detecting threats → exporting reports → visualizing key findings, simulating core functions of a lightweight HIDS/SIEM module.</p>
<br>
<br>
<br>

### 📝 Conclusion:

<p align="left">• The findings confirm that the log analyzer accurately identified abnormal traffic patterns and attack behaviors, with IP <strong>192.168.4.164</strong> emerging as the primary malicious source across all threat categories.</p>

<p align="left">• The high <strong>Requests Per Minute (2908+ RPM)</strong> spikes illustrate clear signs of DoS/DDoS activity, validated by both statistical aggregation and visual analysis.</p>

<p align="left">• Detection of <strong>2620 brute-force errors, 165 SQLi attempts</strong>, and <strong>136 XSS payloads</strong> demonstrates that the system’s signature-based approach effectively captures both low-noise and high-noise threats.</p>

<p align="left">• The modular design of the analyzer is built around parsing, cleaning, grouping, and pattern matching and it ensures the system is scalable, maintainable, and easily adaptable for additional detection rules.</p>

<p align="left">• Visualization outputs further strengthen the investigative workflow by enabling rapid interpretation of attack severity and attacker contribution.</p>

<p align="left">Overall, the project successfully meets its objectives by providing a practical, automated, and insightful intrusion detection tool, laying the groundwork for future enhancements such as real-time monitoring, ML-based anomaly detection, and integration with threat intelligence platforms.</p><br>
<br>
<br>
<br>
