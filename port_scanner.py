"""
Advanced Port Scanner
Created by [Soumit Santra]
© 2025 [Soumit Santra]. All rights reserved.
Advanced Security Tools
A comprehensive port scanning tool with multiple scanning modes
"""
import os
import sys
import socket
import struct
import time
import threading
import queue
import subprocess
import platform
import datetime
import json
import argparse
from tqdm import tqdm
import ipaddress
import ctypes

# Check and install required packages if missing
required_packages = ['colorama', 'tqdm', 'scapy']
missing_packages = []

for package in required_packages:
    try:
        __import__(package)
    except ImportError:
        missing_packages.append(package)

if missing_packages:
    print(f"Installing missing packages: {', '.join(missing_packages)}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing_packages)
        print("All required packages have been installed successfully.")
    except Exception as e:
        print(f"Error installing packages: {e}")
        print("Please install them manually: pip install " + " ".join(missing_packages))
        sys.exit(1)

# Import colorama after ensuring it's installed
from colorama import init, Fore, Back, Style
init(autoreset=True)

# Import scapy for advanced scanning features
try:
    from scapy.all import sr1, IP, TCP, UDP, ICMP, sr
    HAS_SCAPY = True
except ImportError:
    print(f"{Fore.YELLOW}Warning: Scapy import failed. Some advanced scanning features will be limited.{Style.RESET_ALL}")
    HAS_SCAPY = False

# Define global variables
HAS_COLORAMA = True
OPEN_PORTS = []
FILTERED_PORTS = []
CLOSED_PORTS = []
SCAN_RESULTS = {}
HOST = ""
DEFAULT_TIMEOUT = 1.0
MAX_THREADS = 100
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
OS_INFO = ""

# Define port service dictionary
PORT_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Proxy"
}

def print_banner():
    if HAS_COLORAMA:
        banner = f"""
{Fore.MAGENTA}{Style.BRIGHT}  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗    
{Fore.MAGENTA}{Style.BRIGHT}  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗   
{Fore.MAGENTA}{Style.BRIGHT}  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝   
{Fore.MAGENTA}{Style.BRIGHT}  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗   
{Fore.MAGENTA}{Style.BRIGHT}  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║   
{Fore.MAGENTA}{Style.BRIGHT}  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   

"""
    else:
        banner = """

 ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗    
 ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗   
 ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝   
 ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗   
 ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║   
 ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   


"""
    print(banner)

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def validate_hostname(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.gaierror:
        return False

def get_target():
    while True:
        target = input(f"{Fore.GREEN}Enter target IP or hostname: {Style.RESET_ALL}")
        if validate_ip(target) or validate_hostname(target):
            try:
                ip = socket.gethostbyname(target)
                print(f"{Fore.GREEN}Target resolved to IP: {ip}{Style.RESET_ALL}")
                return target
            except socket.gaierror:
                print(f"{Fore.RED}Error resolving hostname. Please try again.{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Invalid IP address or hostname. Please try again.{Style.RESET_ALL}")

def tcp_scan(host, port, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            service = PORT_MAP.get(port, "Unknown")
            try:
                sock.send(b"Hello\r\n")
                banner = sock.recv(1024).decode('utf-8', 'ignore').strip()
            except:
                banner = ""
            OPEN_PORTS.append((port, service, banner))
            SCAN_RESULTS[port] = {"status": "open", "service": service, "banner": banner}
        else:
            CLOSED_PORTS.append(port)
            SCAN_RESULTS[port] = {"status": "closed", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
        sock.close()
    except socket.timeout:
        FILTERED_PORTS.append(port)
        SCAN_RESULTS[port] = {"status": "filtered", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
    except Exception as e:
        FILTERED_PORTS.append(port)
        SCAN_RESULTS[port] = {"status": "error", "service": PORT_MAP.get(port, "Unknown"), "banner": str(e)}

def udp_scan(host, port, timeout):
    if HAS_SCAPY:
        try:
            packet = IP(dst=host)/UDP(dport=port)
            response = sr1(packet, timeout=timeout, verbose=0)
            
            if response is None:
                # No response, might be open or filtered
                OPEN_PORTS.append((port, PORT_MAP.get(port, "Unknown"), ""))
                SCAN_RESULTS[port] = {"status": "open|filtered", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
            elif response.haslayer(ICMP):
                # ICMP "Port Unreachable" indicates port is closed
                CLOSED_PORTS.append(port)
                SCAN_RESULTS[port] = {"status": "closed", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
            else:
                # Got a UDP response
                OPEN_PORTS.append((port, PORT_MAP.get(port, "Unknown"), ""))
                SCAN_RESULTS[port] = {"status": "open", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
        except Exception as e:
            FILTERED_PORTS.append(port)
            SCAN_RESULTS[port] = {"status": "error", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": str(e)}
    else:
        # Fallback UDP scan if scapy is not available
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"", (host, port))
            data, addr = sock.recvfrom(1024)
            OPEN_PORTS.append((port, PORT_MAP.get(port, "Unknown"), ""))
            SCAN_RESULTS[port] = {"status": "open", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
        except socket.timeout:
            # No response could mean open or filtered
            OPEN_PORTS.append((port, PORT_MAP.get(port, "Unknown"), ""))
            SCAN_RESULTS[port] = {"status": "open|filtered", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": ""}
        except Exception as e:
            FILTERED_PORTS.append(port)
            SCAN_RESULTS[port] = {"status": "error", "protocol": "UDP", "service": PORT_MAP.get(port, "Unknown"), "banner": str(e)}

def thread_scan(host, ports, protocol, timeout, pbar=None):
    q = queue.Queue()
    
    # Fill the queue with ports
    for port in ports:
        q.put(port)
    
    def worker():
        while not q.empty():
            port = q.get()
            if protocol == "TCP":
                tcp_scan(host, port, timeout)
            else:
                udp_scan(host, port, timeout)
            if pbar:
                pbar.update(1)
            q.task_done()
    
    # Start the worker threads
    thread_count = min(MAX_THREADS, len(ports))
    threads = []
    
    for _ in range(thread_count):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Wait for the queue to be empty
    q.join()
    
    # Make sure all threads are done
    for t in threads:
        t.join()

def get_elevated_privileges():
    if platform.system().lower() == "windows":
        try:
            # Check if script has admin rights on Windows
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:
        # Check if script has root privileges on Unix/Linux
        return os.geteuid() == 0

def check_permissions():
    print(f"{Fore.CYAN}Checking permissions...{Style.RESET_ALL}")
    if not get_elevated_privileges():
        print(f"{Fore.YELLOW}Warning: This script may work better with elevated privileges.")
        print(f"On Windows: Run as Administrator")
        print(f"On Linux: Run with sudo{Style.RESET_ALL}")
        print(f"Author: Soumit Santra")
        time.sleep(2)

def ping_host(host):
    print(f"{Fore.CYAN}Pinging {host} to check if it's online...{Style.RESET_ALL}")
    
    try:
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", "-w", "1000", host]
        else:
            command = ["ping", "-c", "1", "-W", "1", host]
        
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        if ("TTL=" in output) or ("ttl=" in output):
            print(f"{Fore.GREEN}Host is up!{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.YELLOW}Host might be down or blocking ICMP packets{Style.RESET_ALL}")
            return False
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}Host is down or blocking ICMP packets{Style.RESET_ALL}")
        return False

def traceroute(host):
    print(f"{Fore.CYAN}Running traceroute to {host}...{Style.RESET_ALL}")
    
    command = ["tracert" if platform.system().lower() == "windows" else "traceroute", host]
    
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
        print(f"\n{Fore.GREEN}Traceroute Results:{Style.RESET_ALL}")
        print(output)
        return output
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running traceroute: {e}{Style.RESET_ALL}")
        return None

def os_detection(host):
    global OS_INFO
    
    if HAS_SCAPY:
        print(f"{Fore.CYAN}Attempting OS detection on {host}...{Style.RESET_ALL}")
        # Send TCP packets with different flags and options
        ttl_values = []
        window_sizes = []
        
        try:
            # Test different TCP packets to analyze responses
            tcp_syn = IP(dst=host)/TCP(dport=80, flags="S")
            syn_resp = sr1(tcp_syn, timeout=2, verbose=0)
            
            if syn_resp:
                ttl_values.append(syn_resp.ttl)
                if syn_resp.haslayer(TCP):
                    window_sizes.append(syn_resp.window)
            
            tcp_ack = IP(dst=host)/TCP(dport=80, flags="A")
            ack_resp = sr1(tcp_ack, timeout=2, verbose=0)
            
            if ack_resp:
                ttl_values.append(ack_resp.ttl)
            
            # Simple rule-based OS fingerprinting
            if ttl_values:
                avg_ttl = sum(ttl_values) / len(ttl_values)
                if 60 <= avg_ttl <= 64:
                    os_type = "Linux/Unix/macOS"
                elif 100 <= avg_ttl <= 128:
                    os_type = "Windows"
                else:
                    os_type = "Unknown"
                
                if window_sizes:
                    if 5840 in window_sizes:
                        os_detail = "Linux (newer kernels)"
                    elif 16384 in window_sizes:
                        os_detail = "Windows (newer versions)"
                    elif 65535 in window_sizes:
                        os_detail = "Windows 7/Server 2008"
                    elif 8192 in window_sizes:
                        os_detail = "Windows Vista/Server 2003"
                    elif 4128 in window_sizes:
                        os_detail = "macOS (older versions)"
                    else:
                        os_detail = os_type
                else:
                    os_detail = os_type
                
                OS_INFO = f"Detected OS: {os_detail} (TTL: {avg_ttl:.0f})"
                print(f"{Fore.GREEN}{OS_INFO}{Style.RESET_ALL}")
                return OS_INFO
            else:
                OS_INFO = "OS detection failed - no response"
                print(f"{Fore.YELLOW}{OS_INFO}{Style.RESET_ALL}")
                return OS_INFO
                
        except Exception as e:
            OS_INFO = f"OS detection error: {e}"
            print(f"{Fore.RED}{OS_INFO}{Style.RESET_ALL}")
            return OS_INFO
    else:
        # Fallback method using TTL from ping
        try:
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "1", host]
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            
            if "TTL=" in output or "ttl=" in output:
                ttl_line = [line for line in output.splitlines() if "TTL=" in line or "ttl=" in line][0]
                ttl_val = int(''.join(filter(str.isdigit, ttl_line.split("TTL=")[1].split(" ")[0])))
                
                if 60 <= ttl_val <= 64:
                    os_guess = "Linux/Unix/macOS"
                elif 100 <= ttl_val <= 128:
                    os_guess = "Windows"
                else:
                    os_guess = "Unknown"
                
                OS_INFO = f"Detected OS (based on TTL): {os_guess} (TTL: {ttl_val})"
                print(f"{Fore.GREEN}{OS_INFO}{Style.RESET_ALL}")
                return OS_INFO
            else:
                OS_INFO = "OS detection failed - could not determine TTL"
                print(f"{Fore.YELLOW}{OS_INFO}{Style.RESET_ALL}")
                return OS_INFO
        except Exception as e:
            OS_INFO = f"OS detection error: {e}"
            print(f"{Fore.RED}{OS_INFO}{Style.RESET_ALL}")
            return OS_INFO

def port_scanner(host, ports, timeout=DEFAULT_TIMEOUT, protocol="TCP", scan_name=""):
    global OPEN_PORTS, CLOSED_PORTS, FILTERED_PORTS, SCAN_RESULTS
    
    # Reset global variables for new scan
    OPEN_PORTS = []
    CLOSED_PORTS = []
    FILTERED_PORTS = []
    SCAN_RESULTS = {}
    
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Starting {scan_name} scan of {host} ({len(ports)} ports){Style.RESET_ALL}")
    print(f"{Fore.CYAN}Protocol: {protocol} | Timeout: {timeout}s{Style.RESET_ALL}")
    
    start_time = time.time()
    
    # Create progress bar with different colors for TCP and UDP
    bar_color = Fore.GREEN if protocol == "TCP" else Fore.BLUE
    with tqdm(total=len(ports), desc=f"{bar_color}{protocol} Scan Progress", unit="port", 
              bar_format="{l_bar}%s{bar}%s{r_bar}" % (bar_color, Style.RESET_ALL)) as pbar:
        thread_scan(host, ports, protocol, timeout, pbar)
    
    end_time = time.time()
    scan_time = end_time - start_time
    
    print(f"\n{Fore.GREEN}{Style.BRIGHT}Scan completed in {scan_time:.2f} seconds{Style.RESET_ALL}")
    
    # Print results
    print_scan_results(protocol)
    
    return SCAN_RESULTS

def run_quick_scan(host):
    scan_name = "Quick"
    return port_scanner(host, COMMON_PORTS, DEFAULT_TIMEOUT, "TCP", scan_name)

def run_regular_scan(host):
    scan_name = "Regular"
    ports = list(range(1, 1001))
    return port_scanner(host, ports, DEFAULT_TIMEOUT, "TCP", scan_name)

def run_tcp_intense_scan(host):
    scan_name = "Intense TCP"
    ports = list(range(1, 65536))
    return port_scanner(host, ports, DEFAULT_TIMEOUT, "TCP", scan_name)

def run_udp_intense_scan(host):
    scan_name = "Intense UDP"
    # Scan most common UDP ports
    ports = [53, 67, 68, 69, 123, 135, 137, 138, 139, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353]
    return port_scanner(host, ports, DEFAULT_TIMEOUT * 2, "UDP", scan_name)

def run_tcp_udp_intense_scan(host):
    run_tcp_intense_scan(host)
    run_udp_intense_scan(host)

def run_intense_scan_no_ping(host):
    print(f"{Fore.YELLOW}Skipping ping check and scanning anyway...{Style.RESET_ALL}")
    return run_tcp_intense_scan(host)

def run_ping_scan(host):
    print(f"{Fore.CYAN}Running ping scan on {host}...{Style.RESET_ALL}")
    ping_host(host)

def run_quick_trace_route(host):
    print(f"{Fore.CYAN}Running quick trace route to {host}...{Style.RESET_ALL}")
    return traceroute(host)

def run_slow_comprehensive_scan(host):
    scan_name = "Slow Comprehensive"
    ports = list(range(1, 65536))
    timeout = DEFAULT_TIMEOUT * 2
    
    print(f"{Fore.YELLOW}Warning: This scan is very thorough and will take a significant amount of time.{Style.RESET_ALL}")
    result = port_scanner(host, ports, timeout, "TCP", scan_name)
    
    # Run OS detection
    os_detection(host)
    
    # Run quick UDP scan
    udp_ports = [53, 67, 68, 69, 123, 161, 162, 445, 500, 514, 520, 1434, 1900, 4500, 5353]
    port_scanner(host, udp_ports, timeout * 2, "UDP", "UDP")
    
    return result

def run_os_scan(host):
    print(f"{Fore.CYAN}Running OS detection on {host}...{Style.RESET_ALL}")
    return os_detection(host)

def run_custom_scan(host):
    try:
        start_port = int(input(f"{Fore.GREEN}Enter start port (1-65535): {Style.RESET_ALL}"))
        end_port = int(input(f"{Fore.GREEN}Enter end port (1-65535): {Style.RESET_ALL}"))
        
        if start_port < 1 or start_port > 65535 or end_port < 1 or end_port > 65535 or start_port > end_port:
            print(f"{Fore.RED}Invalid port range. Using default range 1-1000.{Style.RESET_ALL}")
            start_port = 1
            end_port = 1000
        
        scan_speed = int(input(f"{Fore.GREEN}Enter scan speed (0-5, 0=slowest, 5=fastest): {Style.RESET_ALL}"))
        if scan_speed < 0 or scan_speed > 5:
            scan_speed = 3
            print(f"{Fore.YELLOW}Invalid speed. Using default speed (3).{Style.RESET_ALL}")
        
        # Adjust timeout based on scan speed
        timeout_map = {0: 5.0, 1: 3.0, 2: 2.0, 3: 1.0, 4: 0.5, 5: 0.2}
        timeout = timeout_map[scan_speed]
        
        protocol = input(f"{Fore.GREEN}Select protocol (tcp/udp/both): {Style.RESET_ALL}").lower()
        if protocol not in ['tcp', 'udp', 'both']:
            protocol = 'tcp'
            print(f"{Fore.YELLOW}Invalid protocol. Using TCP.{Style.RESET_ALL}")
        
        need_traceroute = input(f"{Fore.GREEN}Run traceroute? (y/n): {Style.RESET_ALL}").lower() == 'y'
        need_os_detection = input(f"{Fore.GREEN}Run OS detection? (y/n): {Style.RESET_ALL}").lower() == 'y'
        
        # Run traceroute if requested
        if need_traceroute:
            traceroute(host)
        
        # Run the port scans based on protocol choice
        scan_name = "Custom"
        ports = list(range(start_port, end_port + 1))
        result = {}
        
        if protocol in ['tcp', 'both']:
            tcp_result = port_scanner(host, ports, timeout, "TCP", f"{scan_name} TCP")
            result.update(tcp_result)
        
        if protocol in ['udp', 'both']:
            # For UDP, we'll use a longer timeout due to its nature
            udp_result = port_scanner(host, ports, timeout * 2, "UDP", f"{scan_name} UDP")
            result.update(udp_result)
        
        # Run OS detection if requested
        if need_os_detection:
            os_detection(host)
        
        return result
    except ValueError:
        print(f"{Fore.RED}Invalid input. Running regular scan instead.{Style.RESET_ALL}")
        return run_regular_scan(host)

def print_scan_results(protocol="TCP"):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}Scan Results for {protocol}:{Style.RESET_ALL}")
    
    if OPEN_PORTS:
        print(f"\n{Fore.GREEN}{Style.BRIGHT}Open Ports:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'PORT':<10}{'SERVICE':<15}{'BANNER':<50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'-'*75}{Style.RESET_ALL}")
        
        for port, service, banner in sorted(OPEN_PORTS):
            banner_display = banner[:47] + "..." if len(banner) > 50 else banner
            print(f"{Fore.GREEN}{port:<10}{service:<15}{banner_display:<50}{Style.RESET_ALL}")
    else:
        print(f"\n{Fore.YELLOW}No open ports found{Style.RESET_ALL}")
    
    if FILTERED_PORTS:
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}Filtered Ports: {len(FILTERED_PORTS)}{Style.RESET_ALL}")
        if len(FILTERED_PORTS) <= 10:
            print(', '.join(map(str, sorted(FILTERED_PORTS))))
        else:
            print(', '.join(map(str, sorted(FILTERED_PORTS)[:10])) + f"... ({len(FILTERED_PORTS) - 10} more)")
    
    if protocol == "TCP":
        print(f"\n{Fore.CYAN}{Style.BRIGHT}Statistics:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Total ports scanned: {len(OPEN_PORTS) + len(CLOSED_PORTS) + len(FILTERED_PORTS)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Open ports: {len(OPEN_PORTS)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Closed ports: {len(CLOSED_PORTS)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Filtered ports: {len(FILTERED_PORTS)}{Style.RESET_ALL}")

def save_results(scan_type):
    save_choice = input(f"\n{Fore.GREEN}Do you want to save the scan results? (y/n): {Style.RESET_ALL}").lower()
    
    if save_choice != 'y':
        return
    
    location_choice = input(f"{Fore.GREEN}Save to current location or custom location? (current/custom): {Style.RESET_ALL}").lower()
    
    if location_choice == 'custom':
        file_path = input(f"{Fore.GREEN}Enter the file path to save: {Style.RESET_ALL}")
        if not file_path.lower().endswith('.txt'):
            file_path += '.txt'
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = f"scan_results_{HOST}_{timestamp}.txt"
    
    try:
        with open(file_path, 'w') as f:
            f.write(f"Port Scanner Results\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Target: {HOST}\n")
            f.write(f"Scan Type: {scan_type}\n")
            f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            if OS_INFO:
                f.write(f"OS Detection: {OS_INFO}\n")
            f.write(f"\nOpen Ports:\n")
            f.write(f"{'-'*50}\n")
            f.write(f"{'PORT':<10}{'SERVICE':<15}{'BANNER':<50}\n")
            f.write(f"{'-'*75}\n")
            
            for port, service, banner in sorted(OPEN_PORTS):
                banner_display = banner[:47] + "..." if len(banner) > 50 else banner
                f.write(f"{port:<10}{service:<15}{banner_display:<50}\n")
            
            f.write(f"\nStatistics:\n")
            f.write(f"{'-'*50}\n")
            f.write(f"Total ports scanned: {len(OPEN_PORTS) + len(CLOSED_PORTS) + len(FILTERED_PORTS)}\n")
            f.write(f"Open ports: {len(OPEN_PORTS)}\n")
            f.write(f"Closed ports: {len(CLOSED_PORTS)}\n")
            f.write(f"Filtered ports: {len(FILTERED_PORTS)}\n")
            
            if FILTERED_PORTS:
                f.write(f"\nFiltered Ports: {len(FILTERED_PORTS)}\n")
                f.write(', '.join(map(str, sorted(FILTERED_PORTS))))
        
        print(f"{Fore.GREEN}Results saved to {file_path}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving results: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Trying to save to current directory...{Style.RESET_ALL}")
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            file_path = f"scan_results_{HOST}_{timestamp}.txt"
            with open(file_path, 'w') as f:
                f.write("Port Scanner Results\n")
                f.write(f"{'='*50}\n\n")
                f.write(f"Target: {HOST}\n")
                f.write(f"Scan Type: {scan_type}\n")
                f.write(f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if OS_INFO:
                    f.write(f"OS Detection: {OS_INFO}\n")
                f.write(f"\nOpen Ports:\n")
                f.write(f"{'-'*50}\n")
                f.write(f"{'PORT':<10}{'SERVICE':<15}{'BANNER':<50}\n")
                f.write(f"{'-'*75}\n")
                
                for port, service, banner in sorted(OPEN_PORTS):
                    banner_display = banner[:47] + "..." if len(banner) > 50 else banner
                    f.write(f"{port:<10}{service:<15}{banner_display:<50}\n")
                
                f.write(f"\nStatistics:\n")
                f.write(f"{'-'*50}\n")
                f.write(f"Total ports scanned: {len(OPEN_PORTS) + len(CLOSED_PORTS) + len(FILTERED_PORTS)}\n")
                f.write(f"Open ports: {len(OPEN_PORTS)}\n")
                f.write(f"Closed ports: {len(CLOSED_PORTS)}\n")
                f.write(f"Filtered ports: {len(FILTERED_PORTS)}\n")
                
                if FILTERED_PORTS:
                    f.write(f"\nFiltered Ports: {len(FILTERED_PORTS)}\n")
                    f.write(', '.join(map(str, sorted(FILTERED_PORTS))))
            print(f"{Fore.GREEN}Results saved to {file_path}{Style.RESET_ALL}")
        except Exception as e2:
            print(f"{Fore.RED}Error saving to current directory: {e2}{Style.RESET_ALL}")

def main():
    global HOST
    
    print_banner()
    check_permissions()  # Add permission check at startup

    # Set socket timeout based on platform
    if platform.system().lower() == "windows":
        socket.setdefaulttimeout(DEFAULT_TIMEOUT)
    else:
        # Linux/Unix systems might need a slightly longer timeout
        socket.setdefaulttimeout(DEFAULT_TIMEOUT * 1.5)

    while True:
        print("=" * 60)
        print(f"{Fore.CYAN}{Style.BRIGHT}Select a scan type:{Style.RESET_ALL}")
        print("=" * 60)
        print(f"{Fore.GREEN}1. Quick scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}2. Regular scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}3. Intense scan all TCP{Style.RESET_ALL}")
        print(f"{Fore.GREEN}4. Intense scan with UDP{Style.RESET_ALL}")
        print(f"{Fore.GREEN}5. Intense TCP + UDP scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}6. Intense scan no ping{Style.RESET_ALL}")
        print(f"{Fore.GREEN}7. Ping scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}8. Quick trace route{Style.RESET_ALL}")
        print(f"{Fore.GREEN}9. Slow comprehensive scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}10. OS scan{Style.RESET_ALL}")
        print(f"{Fore.GREEN}11. Customize scan{Style.RESET_ALL}")
        print(f"{Fore.RED}12. Exit{Style.RESET_ALL}")
        print("=" * 60)
        
        try:
            choice = int(input(f"\n{Fore.YELLOW}Enter your choice (1-12): {Style.RESET_ALL}"))
            
            if choice == 12:
                print(f"\n{Fore.CYAN}Thank you for using Port Scanner! Goodbye!{Style.RESET_ALL}")
                sys.exit(0)
            elif choice < 1 or choice > 12:
                print(f"{Fore.RED}Invalid choice. Please enter a number between 1-12.{Style.RESET_ALL}")
                continue
                
            # Get target after scan type selection
            HOST = get_target()
            ip = socket.gethostbyname(HOST)
            print(f"\n{Fore.CYAN}{Style.BRIGHT}Target: {HOST} ({ip}){Style.RESET_ALL}")
            
            if choice == 1:
                run_quick_scan(ip)
                save_results("Quick scan")
            elif choice == 2:
                run_regular_scan(ip)
                save_results("Regular scan")
            elif choice == 3:
                run_tcp_intense_scan(ip)
                save_results("Intense TCP scan")
            elif choice == 4:
                run_udp_intense_scan(ip)
                save_results("Intense UDP scan")
            elif choice == 5:
                run_tcp_udp_intense_scan(ip)
                save_results("Intense TCP+UDP scan")
            elif choice == 6:
                run_intense_scan_no_ping(ip)
                save_results("Intense scan no ping")
            elif choice == 7:
                run_ping_scan(ip)
            elif choice == 8:
                run_quick_trace_route(ip)
            elif choice == 9:
                run_slow_comprehensive_scan(ip)
                save_results("Slow comprehensive scan")
            elif choice == 10:
                run_os_scan(ip)
            elif choice == 11:
                run_custom_scan(ip)
                save_results("Custom scan")
                
        except ValueError:
            print(f"{Fore.RED}Invalid input. Please enter a number.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.CYAN}Scan interrupted. Exiting...{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            print(f"{Fore.RED}An error occurred: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.CYAN}Program interrupted. Exiting...{Style.RESET_ALL}")
        sys.exit(0)
    except PermissionError:
        print(f"{Fore.RED}Permission denied. Try running with elevated privileges.")
        print(f"Windows: Run as Administrator")
        print(f"Linux: Run with sudo{Style.RESET_ALL}")
        print(f"Author: Soumit Santra")
        sys.exit(1)
