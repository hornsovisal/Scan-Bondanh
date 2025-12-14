import sys
import os


# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
from src.host_discovery.host_discovery import HostScanner
from src.reportings.report_manager import HostReportManager, PortReportManager
from src.IP_Finding.ip_find import IPConfig
from src.port_scanning.port_scanning import PortScanner

def clear_terminal():
    # Prompt the user explicitly and avoid silently defaulting to 'yes'.
    while True:
        try:
            # Print prompt and flush to ensure it appears before input()
            prompt = "Clear screen? (Y/N) [Y]: "
            choice = input(prompt).strip().lower()
        except EOFError:
            # If input is not available, do not clear.
            return

        if choice == '':
            choice = 'y'
        if choice in ('y', 'n'):
            break
        print("Please enter 'Y' or 'N'.")

    if choice == 'y':
        try:
            input("Press Enter to continue...")
        except EOFError:
            # If the terminal doesn't support input, just attempt to clear.
            pass

        # Prefer calling the system clear command which works reliably on most shells
        try:
            if os.name == 'nt':
                rc = os.system('cls')
            else:
                rc = os.system('clear')
            # If the system call failed (non-zero), fall back to ANSI sequence
            if rc != 0:
                print("\033c", end="", flush=True)
        except Exception:
            try:
                print("\033c", end="", flush=True)
            except Exception:
                pass

def main():
    banner = banner = r"""
███████╗ ██████╗ █████╗ ███╗   ██╗    ██████╗  ██████╗ ███╗   ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗████╗  ██║██║  ██║
███████╗██║     ███████║██╔██╗ ██║    ██████╔╝██║   ██║██╔██╗ ██║██║  ██║███████║██╔██╗ ██║███████║
╚════██║██║     ██╔══██║██║╚██╗██║    ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██║██║╚██╗██║██╔══██║
███████║╚██████╗██║  ██║██║ ╚████║    ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║ ╚████║██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝
                                                                                                   
"""
    
    while True:
        print(banner)
        print("\n======== Scan Bondanh ========")
        print("[1] Host Discovery")
        print("[2] Port Scanning")
        print("[3] What is my IP?")
        print("[4] Exit")
        print("==============================")

        choice = input("Choose an option (1-4): ").strip()
        

        match choice:
            case "1":
                # Host Discovery Logic
                scanner = HostScanner()
                start_ip = input("Enter start IP (ex: 192.168.1.1): ").strip()
                end_ip = input("Enter end IP (ex: 192.168.1.254): ").strip()

                try:
                    # Validate IP format
                    for ip in [start_ip, end_ip]:
                        parts = ip.split('.')
                        if len(parts) != 4 or not all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
                            raise ValueError(f"Invalid IP format: {ip}")
                    
                    # generate full ip range list
                    ip_range_list = scanner.icmp.generate_ip_range(start_ip, end_ip) 
                    
                except ValueError as e:
                    print(f"Invalid IP format. Please use valid IP addresses (e.g., 192.168.1.1).")
                    print(f"Error: {e}")
                    # Continue the loop to show the menu again
                    continue 
                
                print(f"Scanning IP range: {start_ip} to {end_ip}...")
                scanner.display(ip_range_list, method="arp")

           
                print("\nScan complete.")
                save = input("Generate report? (Y/N): ").strip().lower()
                if save == 'y':
                    # Get customer information
                    customer_name = input("Enter Customer/Client Name: ").strip()
                    if not customer_name:
                        customer_name = "Network Security Assessment"
                    
                    network_range = f"{start_ip} to {end_ip}"
                    # Create report manager and load cached scan results
                    report_dir = os.path.join(os.path.dirname(__file__), 'reports', 'host_scanner')
                    os.makedirs(report_dir, exist_ok=True)
                    report_manager = HostReportManager(output_dir=report_dir)
                    report_manager.scanner = scanner  # Use the same scanner with cached results
                    report_manager.load_from_cached_scan()  # Load results from cache without re-scanning
                    
                    # Generate professional report with custom metadata
                    report_manager.generate_report(
                        customer_name=customer_name,
                        network_range=network_range,
                        project_by= "Scan Bondanh Team - Horn Sovisal , Kuyseng Marakat , Chhit sovathana"
                    )
                    print("✓ Professional report generated successfully!")
                    clear_terminal()
                else:
                    print("Report generation skipped.")
                    clear_terminal()
                
            case "2":
                # Port Scanning Logic
                print("\n=== Port Scanning ===")
                target = input("Enter target (public IP or domain): ").strip()
                
                scanner = PortScanner()
                ip = scanner.resolve_target(target)

                # Validate target
                if not ip:
                    print("❌ Cannot resolve target.")
                    clear_terminal()
                    continue

                # Block private IP addresses
                if scanner.is_private_ip(ip):
                    print("❌ Private IP detected. Scan blocked for security reasons.")
                    clear_terminal()
                    continue

                print(f"✓ Resolved target → {ip}")
                
                # Perform port scan
                print(f"\nScanning {ip}...")
                results = scanner.scan_ports(ip)

                # Display results in terminal
                print(f"\n{'='*120}")
                print(f"PORT SCAN RESULTS FOR {ip}")
                print(f"{'='*120}\n")
                
                print(f"{'Port':<8}{'Protocol':<12}{'State':<12}{'Identified Banner / Fingerprint':<50}{'Risk':<12}{'Notes':<30}")
                print("-" * 120)

                open_found = False
                for port, status, banner in results:
                    if status == "OPEN":
                        open_found = True
                        port_info = scanner.get_port_info(port)
                        risk_level, notes = scanner.classify_risk(port, banner)
                        
                        # Format display
                        banner_display = banner if banner != "N/A" else f"N/A ({port_info['service']} Detected)"
                        banner_display = banner_display[:48] + ".." if len(banner_display) > 50 else banner_display
                        notes_display = notes[:28] + ".." if len(notes) > 30 else notes
                        
                        print(f"{port:<8}{port_info['protocol']:<12}{'OPEN':<12}{banner_display:<50}{risk_level:<12}{notes_display:<30}")

                if not open_found:
                    print("No open ports found.")

                print("-" * 120)
                
                # Summary
                open_count = sum(1 for _, status, _ in results if status == "OPEN")
                print(f"\nSummary: {open_count} open port(s) detected out of {len(results)} scanned.")

                # Generate report
                print("\nScan complete.")
                save = input("Generate report? (Y/N): ").strip().lower()
                if save == 'y':
                    try:
                        # Get customer information
                        customer_name = input("Enter Customer/Client Name: ").strip()
                        if not customer_name:
                            customer_name = "Network Security Assessment"
                        
                        # Get hostname
                        try:
                            import socket
                            hostname = socket.gethostbyaddr(ip)[0]
                        except:
                            hostname = None
                        
                        # Create report manager
                        report_dir = os.path.join(os.path.dirname(__file__), 'reports', 'port_scanner')
                        os.makedirs(report_dir, exist_ok=True)
                        
                        report_mgr = PortReportManager(output_dir=report_dir)
                        report_mgr.set_target_info(ip, hostname)
                        
                        # Add all results
                        for port, status, banner in results:
                            report_mgr.add_port_result(port, status, banner)
                        
                        # Generate report with customer name
                        report_mgr.generate_report(
                            customer_name=customer_name,
                            project_by="Scan Bondanh Team - Horn Sovisal, Kuyseng Marakat, Chhit Sovathana"
                        )
                        print("✓ Professional report generated successfully!")
                    except Exception as e:
                        print(f"Error generating report: {e}")
                else:
                    print("Report generation skipped.")
                
                clear_terminal()
            case "3":
                try:
                    ip_config = IPConfig()
                    ip_config.display_ipv4()
                except Exception as e:
                    print(f"Error displaying IP configuration: {e}")
                clear_terminal()
            case "4":
                print(" Exiting Scan Bondanh. Goodbye!")
                return 
            
            case _:
                print(f"Invalid option: '{choice}'. Please choose 1, 2, 3, or 4.")
        
if __name__ == "__main__":
    main()