# --- Library Imports ---
from __future__ import annotations   # This will tell the hints to avoid error
import socket     # This one is for network communications
import re     # Check whether the IP is private or not 
import json   # use in scanner_result saving in JSON format(easy to read)
import csv    # use in scanner_result saving in CSV format
import sys    # use to exit the program safely(control how your program start and stop)
from pathlib import Path # use to handle file and directory paths in a clean, especially in cross-platform way
from datetime import datetime # use to get the current date
from concurrent.futures import ThreadPoolExecutor, as_completed #use to run port scans in parallel using multiple threads
from typing import List, Tuple, Dict, Optional   # this will return value is a list of (port, status)

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reportings.report_manager import PortReportManager


# --- Color the output so that it's more readable ---
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except Exception:
    class _C:
        RESET = ""
        BRIGHT = ""
    class Fore:
        RED = GREEN = YELLOW = CYAN = RESET = ""
    Style = _C()


# --- These are common service ports used by many network services---
DEFAULT_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123,
    135, 139, 143, 161, 162, 389, 443, 445, 465, 587,
    631, 636, 993, 995, 1433, 1521, 1723, 3306, 3389,
    5432, 8080, 27017
]


# --- Show the current time in the scanner_result ---
def readable_time() -> str:
    return datetime.now().strftime("%b-%d-%Y_%I-%M-%S_%p")


# =====================================================
# BASE CLASS (PARENT CLASS)
# =====================================================
class BaseScanner:
    def __init__(self, workers: int, timeout: float):
        # Private attributes
        self.__workers = workers
        self.__timeout = timeout
        self.__port_db = {}

        # Load port database
        self._load_port_database()

    def _load_port_database(self):
        """Load port information from config/default_ports.json"""
        config_path = Path(__file__).resolve().parents[2] / "config" / "default_ports.json"
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                for port_info in data.get("common_ports", []):
                    self.__port_db[port_info["port"]] = {
                        "service": port_info["service"],
                        "protocol": port_info["protocol"],
                        "description": port_info["description"]
                    }
        except Exception as e:
            print(f"Warning: Could not load port database: {e}")

    def get_port_info(self, port: int) -> Dict[str, str]:
        """Get port information from database"""
        return self.__port_db.get(port, {
            "service": "Unknown",
            "protocol": "tcp",
            "description": "Unknown service"
        })

    def classify_risk(self, port: int, banner: str = "") -> Tuple[str, str]:
        """
        Classify port risk level based on port number and banner
        Returns (risk_level, notes)
        """
        # High-risk ports
        high_risk = {
            21: "Unencrypted FTP - credentials transmitted in clear text",
            23: "Telnet - unencrypted remote access, highly vulnerable",
            3389: "RDP exposed - common ransomware target",
            445: "SMB exposed - vulnerable to ransomware attacks",
            139: "NetBIOS exposed - information disclosure risk",
            1433: "MS SQL Server exposed - database access risk",
            3306: "MySQL exposed - database access risk",
            5432: "PostgreSQL exposed - database access risk",
            27017: "MongoDB exposed - NoSQL database access risk"
        }
        
        # Medium-risk ports
        medium_risk = {
            80: "HTTP - unencrypted web traffic, data interception possible",
            8080: "HTTP Proxy/Alt - unencrypted, often dev/staging server",
            25: "SMTP - email server, can be abused for spam/relay",
            110: "POP3 - unencrypted email retrieval",
            143: "IMAP - unencrypted email access",
            53: "DNS exposed - potential for DNS amplification attacks"
        }
        
        # Low-risk ports
        low_risk = {
            22: "SSH - encrypted, but ensure strong authentication",
            443: "HTTPS - encrypted web traffic, standard and secure",
            993: "IMAPS - encrypted email (secure)",
            995: "POP3S - encrypted email (secure)",
            587: "SMTP TLS - encrypted email submission"
        }
        
        # Check banner for specific vulnerabilities
        notes = ""
        if port in high_risk:
            risk = "High"
            notes = high_risk[port]
        elif port in medium_risk:
            risk = "Medium"
            notes = medium_risk[port]
        elif port in low_risk:
            risk = "Low"
            notes = low_risk[port]
        else:
            risk = "Medium"
            notes = "Service identified but risk profile unknown"
        
        # Add banner-specific notes
        if banner:
            banner_lower = banner.lower()
            if "werkzeug" in banner_lower or "flask" in banner_lower:
                risk = "High"
                notes = "Development/staging server detected - should not be exposed in production"
            elif "apache" in banner_lower or "nginx" in banner_lower:
                notes += ". Web server banner detected"
            elif "ssh" in banner_lower and "openssh" in banner_lower:
                notes = "Standard SSH service - ensure key-based authentication"
        
        return risk, notes


# --- Methods ---
    def resolve_target(self, target: str) -> str | None:
        """
        It will convert a domain name (example: google.com) into an IP address.

        - If the domain is valid, return its IP address
        - If the domain cannot be resolved, return None

        This prevents the program from crashing when the user
        enters an invalid domain or IP.
        """
        try:
            return socket.gethostbyname(target)
        except Exception:
            return None

    def is_private_ip(self, ip: str) -> bool:
        """
        Check whether the given IP address is private or not.

        Private IP addresses are blocked to prevent scanning
        local or internal networks.
        """
        patterns = [
            r"^10\.",
            r"^192\.168\.",
            r"^127\.",
            r"^169\.254\.",
            r"^172\.(1[6-9]|2[0-9]|3[0-1])\."
        ]
        return any(re.match(p, ip) for p in patterns)

    # using gettter to access to private attributes
    def get_workers(self):
        return self.__workers

    def get_timeout(self):
        return self.__timeout


# =====================================================
# CHILD CLASS (INHERITANCE)
# =====================================================
class PortScanner(BaseScanner):
    def __init__(self):
        # using super(). to call the parent class constructor 
        super().__init__(workers=200, timeout=0.6)

        # using private attribute to store the list of ports to scan
        self.__ports = DEFAULT_PORTS

# --- Methods ---
    def grab_banner(self, ip: str, port: int, timeout: float = 2.0) -> str:
        """
        Attempt to grab service banner from an open port
        Returns banner string or "N/A" if unavailable
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n")
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Clean and format banner
            if banner:
                # Extract first line or meaningful part
                lines = banner.split('\n')
                if lines:
                    first_line = lines[0].strip()
                    # For HTTP responses, extract server info
                    if "HTTP" in first_line and len(lines) > 1:
                        for line in lines[1:]:
                            if "Server:" in line or "server:" in line:
                                return line.split(":", 1)[1].strip()
                    return first_line[:100]  # Limit length
            return "N/A"
        except:
            return "N/A"

    def scan_single_port(self, ip: str, port: int) -> Tuple[int, str, str]:
        """
        Scan a single port on the target IP and grab banner if open

        Returns:
        - (port, "OPEN", banner) if connection succeeds
        - (port, "CLOSED", "") if refused
        - (port, "FILTERED", "") if timed out or protected by firewall
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.get_timeout())
        try:
            sock.connect((ip, port))
            sock.close()
            # Grab banner for open ports
            banner = self.grab_banner(ip, port)
            return port, "OPEN", banner
        except socket.timeout:
            return port, "FILTERED", ""
        except ConnectionRefusedError:
            return port, "CLOSED", ""
        except Exception:
            return port, "CLOSED", ""

    def scan_ports(self, ip: str) -> List[Tuple[int, str, str]]:
        """
        Scan all ports using multithreading for faster performance
        """
        print(f"\n{Fore.CYAN}Scanning {ip} ({len(self.__ports)} ports)...{Style.RESET_ALL}\n")
        results = []

        with ThreadPoolExecutor(max_workers=self.get_workers()) as executor:
            futures = [
                executor.submit(self.scan_single_port, ip, p)
                for p in self.__ports
            ]
            for future in as_completed(futures):
                results.append(future.result())

        return sorted(results, key=lambda x: x[0])

    def save_results(self, results, ip):
        """
        Save port scan results using PortReportManager
        """
        try:
            # Get hostname
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = None
        
        # Create report manager
        report_mgr = PortReportManager()
        report_mgr.set_target_info(ip, hostname)
        
        # Add all results
        for port, status, banner in results:
            report_mgr.add_port_result(port, status, banner)
        
        # Generate report
        report_mgr.generate_report()

    # This is the main program flow 
    def run(self):
        """
        Main execution flow of the port scanner.
        """
        target = input("Enter target (public IP or domain): ").strip()
        ip = self.resolve_target(target)

        # Stop if the domain or IP cannot be resolved
        if not ip:
            print(f"{Fore.RED}❌ Cannot resolve target.{Style.RESET_ALL}")
            return

        # Block private IP addresses
        if self.is_private_ip(ip):
            print(f"{Fore.RED}❌ Private IP detected. Scan blocked.{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}Resolved target → {ip}{Style.RESET_ALL}")

        results = self.scan_ports(ip)

        # Display results in professional table format
        print(f"\n{Fore.CYAN}{'='*120}")
        print(f"PORT SCAN RESULTS FOR {ip}")
        print(f"{'='*120}{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}{'Port':<8}{'Protocol':<12}{'State':<12}{'Identified Banner / Fingerprint':<50}{'Risk':<12}{'Notes':<30}{Style.RESET_ALL}")
        print("-" * 120)

        open_found = False

        for port, status, banner in results:
            if status == "OPEN":
                open_found = True
                port_info = self.get_port_info(port)
                risk_level, notes = self.classify_risk(port, banner)
                
                # Color code based on risk
                if risk_level == "High":
                    risk_color = Fore.RED
                elif risk_level == "Medium":
                    risk_color = Fore.YELLOW
                else:
                    risk_color = Fore.GREEN
                
                # Format banner display
                banner_display = banner if banner != "N/A" else f"N/A ({port_info['service']} Detected)"
                banner_display = banner_display[:48] + ".." if len(banner_display) > 50 else banner_display
                notes_display = notes[:28] + ".." if len(notes) > 30 else notes
                
                print(f"{port:<8}{port_info['protocol']:<12}{'OPEN':<12}{banner_display:<50}{risk_color}{risk_level:<12}{Style.RESET_ALL}{notes_display:<30}")

        if not open_found:
            print(f"{Fore.YELLOW}No open ports found.{Style.RESET_ALL}")

        print("-" * 120)
        
        # Summary
        open_count = sum(1 for _, status, _ in results if status == "OPEN")
        print(f"\n{Fore.CYAN}Summary: {open_count} open port(s) detected out of {len(results)} scanned.{Style.RESET_ALL}")

        # Ask user whether to save results
        if input(f"\n{Fore.YELLOW}Save detailed report? (y/N): {Style.RESET_ALL}").lower() == "y":
            self.save_results(results, ip)

        print(f"\n{Fore.GREEN}Scan completed.{Style.RESET_ALL}")


# --- entry point program ---
if __name__ == "__main__":
    try:
        PortScanner().run()
    except KeyboardInterrupt:
        print("\nScan interrupted.")
        sys.exit(0)
