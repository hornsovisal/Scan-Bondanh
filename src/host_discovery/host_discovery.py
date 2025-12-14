"""Host discovery helpers with ICMP-first and ARP fallback."""
import json
import os
import platform
import socket
import subprocess
import sys
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from scapy.all import ARP, Ether, srp, conf  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency
    SCAPY_AVAILABLE = False


class BaseScanner(ABC):
    def __init__(self):
        self._ports = self._load_ports()
        if SCAPY_AVAILABLE:
            conf.verb = 0

    def _load_ports(self):
        """Load port list from config file"""
        try:
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            
            if not os.path.exists(os.path.join(project_root, "config")):
                project_root = os.getcwd()
                while project_root != "/" and not os.path.exists(os.path.join(project_root, "config")):
                    project_root = os.path.dirname(project_root)
            
            config_path = os.path.join(project_root, "config/default_ports.json")
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("port_list_only", [80, 443])
        except Exception:
            return [80, 443]

    def _check_port(self, ip, port):
        """Check if a port is open"""
        try:
            socket.create_connection((ip, port), timeout=0.5).close()
            return port
        except Exception:
            return None

    def scan_ports(self, ip):
        """Scan ports on target IP"""
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_port, ip, p): p for p in self._ports}
            open_ports = [future.result() for future in as_completed(futures) if future.result()]
        return ",".join(map(str, sorted(open_ports))) if open_ports else "None"

    def resolve_identity(self, ip):
        """Resolve hostname using DNS lookup"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            if hostname and hostname != ip:
                return hostname.split('.')[0] if '.' in hostname else hostname
        except Exception:
            pass
        return ip
    
    def generate_ip_range(self, start_ip, end_ip):
        """Generate IP range from start_ip to end_ip"""
        def ip_to_int(ip):
            parts = ip.split('.')
            return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
        
        def int_to_ip(num):
            return f"{(num >> 24) & 255}.{(num >> 16) & 255}.{(num >> 8) & 255}.{num & 255}"
        
        start_num = ip_to_int(start_ip)
        end_num = ip_to_int(end_ip)
        
        return [int_to_ip(i) for i in range(start_num, end_num + 1)]

    @abstractmethod
    def ping(self, ip):
        """Abstract method to be implemented by subclasses"""
        pass


class ICMPScanner(BaseScanner):
    def ping(self, ip):
        """Fast ICMP ping with timeout and response time."""
        param = "-n" if platform.system().lower() == "windows" else "-c"
        timeout_param = "-w" if platform.system().lower() == "windows" else "-W"
        try:
            import time
            start = time.time()
            subprocess.check_output(
                ["ping", param, "1", timeout_param, "2", ip],
                stderr=subprocess.DEVNULL,
                timeout=2.5
            )
            response_time = int((time.time() - start) * 1000)
            return True, response_time
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False, None
        except Exception:
            return False, None


class ARPScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self._icmp_fallback = ICMPScanner()

    def ping(self, ip):
        """ARP ping with MAC address retrieval."""
        if not SCAPY_AVAILABLE:
            return self._icmp_fallback.ping(ip)
        try:
            import time
            start = time.time()
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast / arp_request, timeout=2, verbose=0)[0]
            if answered:
                response_time = int((time.time() - start) * 1000)
                mac = answered[0][1].hwsrc
                return True, response_time, mac
            return False, None, None
        except Exception:
            result, rtt = self._icmp_fallback.ping(ip)
            return result, rtt, None
    
    def get_mac(self, ip):
        """Get MAC address for an IP."""
        if not SCAPY_AVAILABLE:
            return None
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast / arp_request, timeout=2.0, verbose=0)[0]
            if answered:
                return answered[0][1].hwsrc
        except Exception:
            pass
        return None


class HostScanner:
    def __init__(self):
        self.icmp = ICMPScanner()
        self.arp = ARPScanner()

    def _build_result(self, ip, scanner, label, ping_time=None, mac=None):
        identity = scanner.resolve_identity(ip)
        ports = scanner.scan_ports(ip)
        ping_str = f"{ping_time}ms" if ping_time else "N/A"
        mac_str = mac if mac else "N/A"
        return ip, label, identity, ping_str, mac_str, ports

    def scan_host(self, ip, method="auto", skip_ports=False):
        method = method.lower()
        if method not in ("auto", "icmp", "arp"):
            raise ValueError("method must be 'auto', 'icmp', or 'arp'")

        # For auto mode: try ICMP first, then ARP if ICMP fails
        if method == "auto":
            # Try ICMP
            is_alive_icmp, ping_time_icmp = self.icmp.ping(ip)
            
            if is_alive_icmp:
                # ICMP worked, try to get MAC
                arp_result = self.arp.ping(ip)
                mac = arp_result[2] if len(arp_result) == 3 and arp_result[0] else None
                return self._build_result(ip, self.icmp, "Alive", ping_time_icmp, mac)
            else:
                # ICMP failed, try ARP
                arp_result = self.arp.ping(ip)
                if len(arp_result) == 3:
                    is_alive_arp, ping_time_arp, mac = arp_result
                else:
                    is_alive_arp, ping_time_arp = arp_result
                    mac = None
                
                if is_alive_arp:
                    return self._build_result(ip, self.arp, "Alive", ping_time_arp, mac)
                else:
                    return None  # Dead host
        
        # Single method mode
        if method == "arp":
            primary = self.arp
        else:
            primary = self.icmp

        # Try primary method
        if primary is self.icmp:
            is_alive, ping_time = primary.ping(ip)
            if is_alive:
                mac = self.arp.get_mac(ip) if not skip_ports else None
                scanner_to_use = primary if not skip_ports else self.icmp
                return self._build_result(ip, scanner_to_use, "Alive", ping_time, mac)
        else:
            result = primary.ping(ip)
            if len(result) == 3:
                is_alive, ping_time, mac = result
            else:
                is_alive, ping_time = result
                mac = None
            if is_alive:
                scanner_to_use = primary if not skip_ports else self.arp
                return self._build_result(ip, scanner_to_use, "Alive", ping_time, mac)

        return None  # Dead host

    def scan_hosts(self, ip_range, method="auto", max_workers=100, show_progress=True, alive_only=True):
        total = len(ip_range)
        if total == 0:
            return []

        progress = 0
        alive_count = 0
        last_percent = -1

        def report(step, alive):
            nonlocal last_percent, alive_count
            alive_count += alive
            if not show_progress:
                return
            percent = int(step * 100 / total)
            if percent != last_percent or alive > 0:
                sys.stdout.write(f"\rScanning: {percent}% ({alive_count} alive / {step} scanned)    ")
                sys.stdout.flush()
                last_percent = percent

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(self.scan_host, ip, method): ip for ip in ip_range}
            results = []
            for future in as_completed(futures):
                result = future.result()
                if result is not None:  # Host is alive
                    results.append(result)
                    progress += 1
                    report(progress, 1)
                else:
                    if not alive_only:
                        ip = futures[future]
                        results.append((ip, "Dead", "N/A", "N/A", "N/A", "N/A"))
                    progress += 1
                    report(progress, 0)

        if show_progress:
            sys.stdout.write("\n")

        results.sort(key=lambda x: tuple(int(part) for part in x[0].split(".")))
        return results

    def scan(self, ip_range, method="auto", max_workers=50, alive_only=True, show_progress=True):
        """Scan hosts and cache results. Returns results list."""
        print(f"\nStarting scan of {len(ip_range)} IPs...\n")
        self._cached_results = self.scan_hosts(ip_range, method, max_workers, show_progress=show_progress, alive_only=alive_only)
        return self._cached_results
    
    def get_cached_results(self):
        """Get cached scan results without re-scanning"""
        return self._cached_results
    
    def display(self, ip_range=None, method="auto", max_workers=50, alive_only=True):
        """Display scan results. If ip_range is None, uses cached results."""
        if ip_range is not None:
            results = self.scan(ip_range, method, max_workers, alive_only)
        else:
            results = self._cached_results
        
        print(f"\n{'='*120}")
        print(f"Found {len(results)} alive host(s)")
        print(f"{'='*120}")
        print(f"{'IP':<16} {'Status':<8} {'Hostname':<25} {'Ping':<8} {'MAC Address':<18} {'Ports':<30}")
        print("-" * 120)
        
        for ip, status, identity, ping_time, mac, ports in results:
            print(f"{ip:<16} {status:<8} {identity:<25} {ping_time:<8} {mac:<18} {ports:<30}")
        
        print("="*120)
        return results


if __name__ == "__main__":
    scanner = HostScanner()
    
    # Method 2: Cross-subnet range (e.g., 10.12.0.1 to 10.12.3.0)
    sample_range = scanner.icmp.generate_ip_range("172.23.3.1", "172.23.3.254")
    
    scanner.display(sample_range, method="auto")






