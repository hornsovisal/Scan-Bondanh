import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from host_discovery.host_discovery import HostScanner

#initialize scanner
banner = banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  ██████╗ ███╗   ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗████╗  ██║██║  ██║
███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██║   ██║██╔██╗ ██║██║  ██║███████║██╔██╗ ██║███████║
╚════██║██║     ██╔══██║██║╚██╗██║    ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██║██║╚██╗██║██╔══██║
███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║ ╚████║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                                                   
                                       
"""
def main():
    print(banner)
    print("======== Scan Bondanh ========")
    print("[1] Host Discovery")
    print("[2] Port Scanning")
    print("[3] Exit")
    print("==============================")

    choice = input("Choose an option (1, 2, 3): ").strip()
    hosts = []
    results = {}
    #Host Discovery
    
    if choice == "1":
        scanner = HostScanner()
        start_ip = input("Enter start IP (ex: 192.168.1.1): ").strip()
        end_ip = input("Enter end IP (ex: 192.168.1.254): ").strip()

        try:
            # Validate IP format
            for ip in [start_ip, end_ip]:
                parts = ip.split('.')
                if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                    raise ValueError(f"Invalid IP format: {ip}")
            
            ip_range_list = scanner.icmp.generate_ip_range(start_ip, end_ip)
            
        except ValueError as e:
            print(f"Invalid IP format. Please use valid IP addresses (e.g., 192.168.1.1).")
            print(f"Error: {e}")
            return
        
        print(f"Scanning IP range: {start_ip} to {end_ip}...")
        scanner.display(ip_range_list,method="arp")
        

    #Port Scanning

    elif choice == "2":
        pass
    elif choice == "3":
        print(" Exiting Scan Bondanh. Goodbye!")
        return
    else:
        print("Invalid option. Exiting.")
        return


    #report 

    print("\nScan complete.")
    save = input("Generate report? (Y/N): ").strip().lower()

    if save == "y":
        pass
    else:
        pass

if __name__ == "__main__":
    main()