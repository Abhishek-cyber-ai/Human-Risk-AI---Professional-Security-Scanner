# 🛡️ Human Risk AI - Professional Security Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)
![Security](https://img.shields.io/badge/Security-Cybersecurity-red.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 📌 Overview

**Human Risk AI** is an advanced cybersecurity monitoring and device security scanner designed to identify suspicious files, risky processes, unusual network connections, and potential security threats in real time.

The application provides a modern web-based dashboard for monitoring device activity, performing full system scans, generating detailed security reports, and helping users detect potentially malicious behavior on their systems.

---

## ✨ Key Features

### 🔍 Real-Time Monitoring

* Live CPU and memory monitoring
* Active process inspection
* Network connection analysis
* Recent file activity tracking
* Continuous security assessment

### 🛡️ Security Scanning

* Recursive device file scanning
* Detection of suspicious file extensions
* SHA-256 hash generation
* Hidden file detection
* Large file analysis
* Risk score calculation

### ⚠️ Threat Detection

* Suspicious process identification
* High CPU usage monitoring
* Unusual network connection alerts
* Risk-based threat classification
* Executable file monitoring

### 📊 Professional Reports

Generate reports in:

* JSON
* TXT
* HTML

Reports include:

* Scan statistics
* System information
* Suspicious activities
* Security recommendations
* Detailed file analysis

### 🌐 Modern Web Dashboard

* Professional UI
* Real-time updates
* Interactive tabs
* Live risk scoring
* Responsive design

---

# 📸 Dashboard Modules

## Live Monitoring

* System Statistics
* Device Risk Assessment
* Running Processes
* Suspicious Activities
* Network Connections
* Recent Files

## Scan Results

* Total files scanned
* Suspicious files detected
* Scan duration
* Security logs

## Reports

* Download JSON reports
* Download TXT reports
* Download HTML reports

---

# 🏗️ Project Architecture

```text
Human Risk AI
│
├── Device Scanner Engine
│   ├── File Scanner
│   ├── Process Monitor
│   ├── Network Monitor
│   └── Activity Analyzer
│
├── Threat Detection Engine
│   ├── Risk Scoring
│   ├── Suspicious Process Detection
│   ├── Hidden File Detection
│   └── Executable Analysis
│
├── Report Generator
│   ├── JSON Reports
│   ├── TXT Reports
│   └── HTML Reports
│
└── Web Dashboard
    ├── Live Monitoring
    ├── Scan Results
    └── Report Downloads
```

---

# ⚙️ Requirements

## Python Version

```bash
Python 3.8+
```

## Required Packages

```bash
pip install requests
pip install psutil
```

Or:

```bash
pip install -r requirements.txt
```

### requirements.txt

```txt
requests
psutil
```

---

# 🚀 Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/human-risk-ai-security-scanner.git

cd human-risk-ai-security-scanner
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Usage

Run the application:

```bash
python "Human Risk AI Security Scanner.py"
```

Server will start on:

```text
http://localhost:5000
```

Open your browser and visit:

```text
http://localhost:5000
```

---

# 🔍 How Scanning Works

### Step 1

Collect system information

### Step 2

Analyze running processes

### Step 3

Inspect active network connections

### Step 4

Detect suspicious activities

### Step 5

Scan files recursively

### Step 6

Calculate risk scores

### Step 7

Generate security reports

---

# 📊 Risk Scoring Logic

The scanner assigns risk scores based on:

| Condition           | Score   |
| ------------------- | ------- |
| Hidden File         | +30     |
| Large File (>100MB) | +20     |
| Suspicious Filename | +15     |
| Executable Script   | +10     |
| Suspicious Activity | Dynamic |

### Risk Levels

| Score    | Level    |
| -------- | -------- |
| 0 - 29   | Low      |
| 30 - 59  | Medium   |
| 60 - 84  | High     |
| 85 - 100 | Critical |

---

# 📁 Supported File Extensions

```text
.exe
.dll
.scr
.bat
.cmd
.ps1
.vbs
.js
.jar
.apk
.msi
.com
.zip
.rar
.docm
.xlsm
.pptm
```

---

# 📄 Report Formats

## JSON Report

Best for:

* Automation
* SIEM integration
* API consumption

## TXT Report

Best for:

* Quick review
* Sharing findings
* Documentation

## HTML Report

Best for:

* Professional presentations
* Security audits
* Client reporting

---

# 🔐 Security Features

* SHA-256 File Hashing
* Suspicious Process Detection
* Network Activity Monitoring
* Risk-Based Classification
* Hidden File Analysis
* Device Health Monitoring

---

# 💻 Technology Stack

| Technology | Purpose             |
| ---------- | ------------------- |
| Python     | Backend Engine      |
| HTTPServer | Local Web Server    |
| HTML5      | User Interface      |
| CSS3       | Styling             |
| JavaScript | Real-Time Dashboard |
| Psutil     | System Monitoring   |
| Requests   | API Communication   |

---

# 📂 Project Structure

```text
human-risk-ai-security-scanner/
│
├── Human Risk AI Security Scanner.py
├── README.md
├── requirements.txt
├── LICENSE
│
└── reports/
    ├── report.json
    ├── report.txt
    └── report.html
```

---

# 👨‍💻 Author

### Abhishek Rampariya

Cybersecurity Researcher & Developer

📧 Email:
[rampariyaabhishek@gmail.com](mailto:rampariyaabhishek@gmail.com)

💻 GitHub:
https://github.com/abhishekrampariya

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a new feature branch

```bash
git checkout -b feature/new-feature
```

3. Commit changes

```bash
git commit -m "Added new feature"
```

4. Push branch

```bash
git push origin feature/new-feature
```

5. Open Pull Request

---

# ⚠️ Disclaimer

This project is intended for:

* Educational purposes
* Security research
* Authorized security monitoring

Users are responsible for complying with all applicable laws and regulations when using this software.

---

# 📜 License

This project is licensed under the MIT License.

---

## ⭐ Support

If you found this project useful:

⭐ Star the repository

🍴 Fork the project

📢 Share it with the cybersecurity community

---

**Human Risk AI — Real-Time Human Behavior Cybersecurity Engine**
