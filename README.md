# Scan-Bondanh: Network Scanning & Security Assessment Tool

**Scan-Bondanh** is a lightweight, educational, and multi-threaded network scanning tool written in Python. It is designed to perform essential network reconnaissance, including host discovery, detailed port scanning, and service detection, providing clear reports for system administrators and cybersecurity students.

---

## Key Features

- **Host Discovery:** Uses multiple methods to reliably detect active hosts: ICMP ping, ARP scanning (local subnet).
- **High-Speed Scanning:** Implements **multi-threading** for efficient and rapid port scanning across large ranges.
- **Service Detection:** Attempts **banner grabbing** to identify running services (e.g., SSH, HTTP) on open ports.
- **Customizable:** Scan behavior is controlled via external configuration files (`.json`, `.yaml`).
- **Reporting:** Generates structured, machine-readable **JSON** and human-readable **TXT** reports.
- **Modular Architecture:** Built using an Object-Oriented Programming (OOP) approach for easy testing and future expansion.

---

## Project Setup

### Prerequisites

- **Python 3 or higher** (Python 3.13+ recommended)
- **pip** (Python package installer)
- **Administrator/sudo privileges** (required for ARP scanning and raw socket operations)

### Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/hornsovisal/Scan-Bondanh.git
   cd Scan-Bondanh
   ```
2. **Install Dependencies:**
   All necessary external libraries are listed in `requirements.txt`.

   ```bash
   pip install -r requirements.txt
   ```

   **Or with pip3:**

   ```bash
   pip3 install -r requirements.txt
   ```
3. **Verify Installation:**
   Run the setup verification script to ensure all dependencies are installed correctly:

   ```bash
   python3 setup_verify.py
   ```

   You should see:

   ```
   ✓ All required dependencies are installed!
   You can now run: python3 main.py
   ```

### Required Dependencies

- **netifaces** (>=0.11.0) - Network interface information
- **python-docx** (>=0.8.11) - Professional report generation
- **colorama** (>=0.4.6) - Colored terminal output
- **scapy** (>=2.5.0) - Optional, for advanced ARP scanning (falls back to ICMP if not installed)

> **Note:** Built-in modules like `socket`, `json`, `re`, `pathlib`, `datetime`, and `typing` are part of Python's standard library and don't need separate installation.

## 🧩 Basic Usage

To start **Scan-Bondanh**, simply run the main script:
`python3 main.py`
Once executed, the tool displays an ASCII banner followed by the main menu:

    ```
    ======== Scan Bondanh ========     
    [1] Host Discovery    
    [2] Port Scanning     
    [3] What is my IP?     
    [4] Exit     
    ==============================     
    Choose an option (1, 2, 3):  
    ```

### 🔎 1. Host Discovery

Select this option to scan a network for active hosts.
You will be prompted to enter an IP range (for example, `192.168.1.1-192.168.1.254`), and the tool will list all reachable devices on that network.

### 🚪 2. Port Scanning

Use this option to check for open ports on a specific target.
You will be asked to enter a target IP or domain (e.g., `cadt.edu.kh`), and the scanner will test common or specified ports to identify what services are running.

### 🌐 3. What is my IP?

Displays your **IP address** and may also show additional local network information.

### ❌ 4. Exit

Closes the program.

## 🧱 Project Structure

The project is organized as a professional Python package (`py_scan_tool`) to ensure modularity and clean separation of duties.

| Directory/File                       | Purpose                                                          | Key Files/Notes                            |
| ------------------------------------ | ---------------------------------------------------------------- | ------------------------------------------ |
| **📁`src/`**                 | **The Core Python Package**(Source Code)                   | Contains all executable logic.             |
| ├── 📁`host_discovery/`         | Handles**Host Detection**using ICMP, ARP, and TCP methods. | host_discovery.py                          |
| ├── 📁`port_scanning/`          | Manages**Concurrency**and raw socket connections.          | `port_discovery.py`                      |
| ├── 📁`reporting/`              | Handles**Report Generation**and file output.               | `report_manager.py`                      |
| ├── 📁`IP_Finding/`             | handole find IP function                                         | ip_finding.py                              |
| ├── 📄**`main.py`**       | **Primary Entry Point (CLI or GUI)**                       | the entire scan process.                   |
| 📁`config/`                        | **Tool Settings**                                          | External files to configure tool behavior. |
| ├── 📄`default_ports.json`      | List of commonly scanned ports (e.g., 80, 443, 22).              |                                            |
| **📁`reports/`**             | **Scan Output**                                            | Stores all generated scan reports.         |
| └── 📄`scan_results_YYMMDD.pdf` | Example output file.                                             |                                            |
| **📄`requirements.txt`**     | **Dependencies**                                           | List of all required Python libraries.     |
| **📄`__init__py`**           | **Python Package**                                         | Mark a directory as a Python package.      |
| **📄`setup_verify.py`**      | **Python code**                                         | make sure all dependency install properly |

## 🤝 Contribution

**Prepared By:** Horn Sovisal; Kuyseng Marakat; Chhit Sovathana

**Course:** Python for Cyber Security

**Course Info** : This course introduces Python programming. with a strong focus on Object-Oriented Programming (OOP) and its application in cybersecurity.

**Lecturer** : Mr. Han Leangsiv

**Department:** Telecom and Networking, Cyber Security, Cambodia Accademy of Digital Technology(CADT)
